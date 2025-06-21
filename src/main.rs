use chrono::Local;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle, style::TemplateError};
use reqwest::{Client, multipart};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self},
    path::{Path, PathBuf},
};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;

const CHUNK_SIZE: u64 = 40 * 1024 * 1024; // 40MB
const HISTORY_FILE: &str = "upload_history.json";
const CONFIG_FILE: &str = "config.json";
const TIMEOUT_SECONDS: u64 = 120;

#[derive(Debug, Serialize, Deserialize)]
struct UploadRecord {
    file_name: String,
    upload_time: String,
    urls: Vec<String>,
    size: u64,
    chunks: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadHistory {
    records: Vec<UploadRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    auth_token: Option<String>,
    cookies: Option<HashMap<String, String>>,
}

#[derive(Debug)]
enum UploadError {
    IOError(io::Error),
    ReqwestError(reqwest::Error),
    SerdeError(serde_json::Error),
    AuthError(String),
    SevenZipError(String),
    TemplateError(TemplateError),
    Other(String),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::IOError(e) => write!(f, "IO Error: {}", e),
            UploadError::ReqwestError(e) => write!(f, "HTTP Error: {}", e),
            UploadError::SerdeError(e) => write!(f, "Serialization Error: {}", e),
            UploadError::AuthError(e) => write!(f, "Authentication Error: {}", e),
            UploadError::SevenZipError(e) => write!(f, "7-Zip Error: {}", e),
            UploadError::TemplateError(e) => write!(f, "Template Error: {}", e),
            UploadError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for UploadError {}

impl From<io::Error> for UploadError {
    fn from(err: io::Error) -> Self {
        UploadError::IOError(err)
    }
}

impl From<reqwest::Error> for UploadError {
    fn from(err: reqwest::Error) -> Self {
        UploadError::ReqwestError(err)
    }
}

impl From<serde_json::Error> for UploadError {
    fn from(err: serde_json::Error) -> Self {
        UploadError::SerdeError(err)
    }
}

impl From<TemplateError> for UploadError {
    fn from(err: TemplateError) -> Self {
        UploadError::TemplateError(err)
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Login to Codemao service
    Login {
        #[clap(short, long)]
        identity: String,
        #[clap(short, long)]
        password: String,
    },
    /// Upload a file
    Upload {
        #[clap(short, long)]
        file_path: String,
        #[clap(short, long, default_value = "aumiao")]
        save_path: String,
    },
    /// Download a file
    Download {
        #[clap(short, long)]
        url: String,
        #[clap(short, long)]
        output_path: String,
    },
    /// Merge downloaded chunks
    Merge {
        #[clap(short, long)]
        output_file: String,
        #[clap(short, long)]
        chunks: Vec<String>,
    },
    /// Show upload history
    History,
}

struct FileUploader {
    client: Client,
    config: Config,
}

impl FileUploader {
    fn new() -> Result<Self, UploadError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECONDS))
            .build()?;
        let config = Self::load_config()?;
        Ok(FileUploader { client, config })
    }

    fn load_config() -> Result<Config, UploadError> {
        if Path::new(CONFIG_FILE).exists() {
            let content = fs::read_to_string(CONFIG_FILE)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Config {
                auth_token: None,
                cookies: None,
            })
        }
    }

    fn save_config(&self) -> Result<(), UploadError> {
        let content = serde_json::to_string_pretty(&self.config)?;
        fs::write(CONFIG_FILE, content)?;
        Ok(())
    }

    fn load_history() -> Result<UploadHistory, UploadError> {
        if Path::new(HISTORY_FILE).exists() {
            let content = fs::read_to_string(HISTORY_FILE)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(UploadHistory {
                records: Vec::new(),
            })
        }
    }

    fn save_history(history: &UploadHistory) -> Result<(), UploadError> {
        let content = serde_json::to_string_pretty(history)?;
        fs::write(HISTORY_FILE, content)?;
        Ok(())
    }

    async fn login(&mut self, identity: &str, password: &str) -> Result<(), UploadError> {
        let pid = "65edCTyg";
        println!("Logging in with identity: {}, pid: {}", identity, pid);
        
        let response = self
            .client
            .post("https://api.codemao.cn/tiger/v3/web/accounts/login")
            .json(&serde_json::json!({
                "identity": identity,
                "password": password,
                "pid": pid,
            }))
            .send()
            .await
            .map_err(|e| {
                println!("Request error: {:?}", e);
                UploadError::ReqwestError(e)
            })?;

        // 先读取响应文本
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            println!("Error reading response text: {:?}", e);
            UploadError::ReqwestError(e)
        })?;

        println!("Login response status: {}, content: {}", status, text);

        if !status.is_success() {
            return Err(UploadError::AuthError(format!(
                "Login failed with status: {}\nResponse: {}",
                status, text
            )));
        }

        // 解析响应获取token
        let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            println!("JSON parse error: {:?}, content: {}", e, text);
            UploadError::SerdeError(e)
        })?;
        
        println!("Parsed JSON: {:?}", json);

        if let Some(token) = json["auth"]["token"].as_str() {
            println!("Login successful! Token: {}", token);
            self.config.auth_token = Some(token.to_string());
            self.save_config()?;
            Ok(())
        } else {
            Err(UploadError::AuthError(format!(
                "No token in response: {}",
                text
            )))
        }
    }

    async fn upload_file(
        &self,
        file_path: &Path,
        save_path: &str,
    ) -> Result<Vec<String>, UploadError> {
        let file_size = fs::metadata(file_path)?.len();

        if file_size <= CHUNK_SIZE {
            let url = self.upload_to_pgaot(file_path, save_path).await?;
            Ok(vec![url])
        } else {
            let chunks = self.split_and_upload(file_path, save_path).await?;
            Ok(chunks)
        }
    }

    async fn upload_to_pgaot(
        &self,
        file_path: &Path,
        save_path: &str,
    ) -> Result<String, UploadError> {
        let file_bytes = std::fs::read(file_path)?;
        let file_name = file_path.file_name().unwrap().to_str().unwrap();

        let form = multipart::Form::new()
            .text("path", save_path.to_string())
            .part(
                "file",
                multipart::Part::bytes(file_bytes)
                    .file_name(file_name.to_string())
                    .mime_str("application/octet-stream")?,
            );

        let response = self
            .client
            .post("https://api.pgaot.com/user/up_cat_file")
            .multipart(form)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(UploadError::Other(format!(
                "Upload failed with status: {}\n{}",
                status,
                error_text
            )));
        }

        #[derive(Deserialize)]
        struct PgaotUploadResponse {
            url: String,
        }

        let response_json: PgaotUploadResponse = response.json().await?;
        Ok(response_json.url)
    }

    async fn split_and_upload(
        &self,
        file_path: &Path,
        save_path: &str,
    ) -> Result<Vec<String>, UploadError> {
        let temp_dir = tempdir()?;
        let chunk_paths = self.create_chunks(file_path, temp_dir.path())?;

        let pb = ProgressBar::new(chunk_paths.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )?
                .progress_chars("#>-"),
        );

        let mut urls = Vec::new();
        for chunk in &chunk_paths {
            let url = self.upload_to_pgaot(chunk, save_path).await?;
            urls.push(url);
            pb.inc(1);
        }

        pb.finish_with_message("Upload completed");
        Ok(urls)
    }

    fn check_7z_exists() -> Result<(), UploadError> {
        let status = std::process::Command::new("7z")
            .arg("--help")
            .status()
            .map_err(|_| UploadError::SevenZipError("7z not found in PATH".into()))?;

        if status.success() {
            Ok(())
        } else {
            Err(UploadError::SevenZipError("7z command failed".into()))
        }
    }

    fn create_chunks(
        &self,
        file_path: &Path,
        output_dir: &Path,
    ) -> Result<Vec<PathBuf>, UploadError> {
        Self::check_7z_exists()?;

        let file_stem = file_path.file_stem().unwrap().to_str().unwrap();

        let output_path = output_dir.join(format!("{}.7z", file_stem));

        let status = std::process::Command::new("7z")
            .arg("a")
            .arg(format!("-v{}m", CHUNK_SIZE / (1024 * 1024)))
            .arg("-mx0")
            .arg(&output_path)
            .arg(file_path)
            .status()
            .map_err(|e| UploadError::SevenZipError(format!("Failed to execute 7z: {}", e)))?;

        if !status.success() {
            return Err(UploadError::SevenZipError("7z compression failed".into()));
        }

        // 查找所有分块文件
        let mut chunks = Vec::new();
        let mut part = 1;

        loop {
            let chunk_name = format!("{}.7z.{:03}", file_stem, part);
            let chunk_path = output_dir.join(chunk_name);

            if !chunk_path.exists() {
                if part == 1 {
                    // 检查是否有单个文件（未分割）
                    let single_file = output_dir.join(format!("{}.7z", file_stem));
                    if single_file.exists() {
                        chunks.push(single_file);
                    }
                }
                break;
            }

            chunks.push(chunk_path);
            part += 1;
        }

        Ok(chunks)
    }

    async fn download_file(&self, url: &str, output_path: &str) -> Result<(), UploadError> {
        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(UploadError::Other(format!(
                "Download failed with status: {}",
                response.status()
            )));
        }

        let total_size = response.content_length().unwrap_or(0);
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"),
        );

        let mut file = tokio::fs::File::create(output_path).await?;
        
        // 使用更可靠的方式下载
        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();

        while let Some(item) = stream.next().await {
            let chunk = item?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            pb.set_position(downloaded);
        }

        pb.finish_with_message("Download completed");
        Ok(())
    }

    fn merge_chunks(output_file: &str, chunks: &[String]) -> Result<(), UploadError> {
        let output_path = Path::new(output_file);
        let mut output = File::create(output_path)?;

        for chunk_path in chunks {
            let mut chunk_file = File::open(chunk_path)?;
            io::copy(&mut chunk_file, &mut output)?;
        }

        Ok(())
    }

    fn add_to_history(&self, record: UploadRecord) -> Result<(), UploadError> {
        let mut history = Self::load_history()?;
        history.records.push(record);
        Self::save_history(&history)
    }

    fn show_history(&self) -> Result<(), UploadError> {
        let history = Self::load_history()?;

        println!("Upload History:");
        println!("{:-<80}", "");
        for (i, record) in history.records.iter().enumerate() {
            println!("Record #{}", i + 1);
            println!("File: {}", record.file_name);
            println!("Time: {}", record.upload_time);
            println!("Size: {} bytes ({} chunks)", record.size, record.chunks);
            println!("URLs:");
            for url in &record.urls {
                println!("  - {}", url);
            }
            println!("{:-<80}", "");
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut uploader = FileUploader::new()?;

    match args.command {
        Commands::Login { identity, password } => {
            match uploader.login(&identity, &password).await {
                Ok(_) => println!("Login successful! Token saved."),
                Err(e) => {
                    eprintln!("Login failed: {}", e);
                    if let UploadError::ReqwestError(ref reqwest_err) = e {
                        eprintln!("Reqwest error details: {:?}", reqwest_err);
                    }
                    return Err(e.into());
                }
            }
        }
        Commands::Upload {
            file_path,
            save_path,
        } => {
            let path = Path::new(&file_path);
            if !path.exists() {
                return Err(UploadError::Other("File not found".into()).into());
            }

            let file_size = fs::metadata(path)?.len();
            let file_name = path.file_name().unwrap().to_str().unwrap().to_string();

            println!(
                "Uploading {} ({} bytes) to save path: {}...",
                file_name, file_size, save_path
            );

            match uploader.upload_file(path, &save_path).await {
                Ok(urls) => {
                    println!("\nUpload successful! URLs:");
                    for url in &urls {
                        println!("- {}", url);
                    }

                    let record = UploadRecord {
                        file_name,
                        upload_time: Local::now().to_rfc3339(),
                        urls,
                        size: file_size,
                        chunks: if file_size > CHUNK_SIZE {
                            (file_size as f64 / CHUNK_SIZE as f64).ceil() as usize
                        } else {
                            1
                        },
                    };

                    uploader.add_to_history(record)?;
                }
                Err(e) => {
                    eprintln!("Upload failed: {}", e);
                    return Err(e.into());
                }
            }
        }
        Commands::Download { url, output_path } => {
            println!("Downloading from {} to {}...", url, output_path);
            uploader.download_file(&url, &output_path).await?;
            println!("\nDownload completed: {}", output_path);
        }
        Commands::Merge {
            output_file,
            chunks,
        } => {
            println!("Merging {} chunks to {}...", chunks.len(), output_file);
            FileUploader::merge_chunks(&output_file, &chunks)?;
            println!("Merge completed: {}", output_file);
        }
        Commands::History => {
            uploader.show_history()?;
        }
    }

    Ok(())
}