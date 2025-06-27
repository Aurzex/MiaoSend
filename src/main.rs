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
    process::{Command, Stdio},
};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use rand::distr::Alphanumeric;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};


const CHUNK_SIZE: u64 = 15 * 1024 * 1024; // 15MB
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
        #[clap(long)] // 新增选项：是否加密短文本
        encrypt: bool,
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
    /// Download from short text
    DownloadFromText {
        #[clap(short, long)]
        text: String,
        #[clap(short, long)] // 解密密码（如果有）
        password: Option<String>,
        #[clap(short, long)]
        output_path: String,
    },
}

// 短文本数据结构
#[derive(Serialize, Deserialize)]
struct ShortTextData {
    urls: Vec<String>,
    original_file_name: String,
    chunk_count: usize,
    encrypted: bool,
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
        let response_text = response.text().await?;  // 获取原始响应文本

        // 调试输出
        println!("Upload response (status {}): {}", status, response_text);

        if !status.is_success() {
            return Err(UploadError::Other(format!(
                "Upload failed with status: {}\n{}",
                status, response_text
            )));
        }

        // 尝试解析响应
        match serde_json::from_str::<serde_json::Value>(&response_text) {
            Ok(json) => {
                // 检查是否有"url"字段
                if let Some(url) = json["url"].as_str() {
                    return Ok(url.to_string());
                }
                
                // 检查是否有"data"字段，其中包含"url"
                if let Some(data) = json["data"].as_object() {
                    if let Some(url) = data.get("url").and_then(|v| v.as_str()) {
                        return Ok(url.to_string());
                    }
                }
                
                // 检查是否有"path"字段
                if let Some(path) = json["path"].as_str() {
                    return Ok(format!("https://static.codemao.cn/{}", path));
                }
                
                // 如果以上都没有，返回原始文本中的URL部分
                Err(UploadError::Other(format!(
                    "Unexpected response format: {}",
                    response_text
                )))
            }
            Err(_) => {
                // 如果JSON解析失败，尝试从文本中提取URL
                if let Some(start) = response_text.find("http://") {
                    if let Some(end) = response_text[start..].find('"') {
                        return Ok(response_text[start..start+end].to_string());
                    }
                }
                if let Some(start) = response_text.find("https://") {
                    if let Some(end) = response_text[start..].find('"') {
                        return Ok(response_text[start..start+end].to_string());
                    }
                }
                
                Err(UploadError::Other(format!(
                    "Failed to parse response: {}",
                    response_text
                )))
            }
        }
    }

    async fn split_and_upload(
        &self,
        file_path: &Path,
        save_path: &str,
    ) -> Result<Vec<String>, UploadError> {
        let temp_dir = tempdir()?;
        let chunk_paths = self.create_chunks(file_path, temp_dir.path())?;

        println!("Starting upload of {} chunks...", chunk_paths.len());
        let pb = ProgressBar::new(chunk_paths.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )?
                .progress_chars("#>-"),
        );

        let mut urls = Vec::new();
        for (index, chunk) in chunk_paths.iter().enumerate() {
            println!("Uploading chunk {}/{}: {}", index + 1, chunk_paths.len(), chunk.display());
            let url = self.upload_to_pgaot(chunk, save_path).await?;
            println!("  Chunk uploaded to: {}", url);
            urls.push(url);
            pb.inc(1);
        }

        pb.finish_with_message("Upload completed");
        println!("All {} chunks uploaded successfully", urls.len());
        Ok(urls)
    }

    fn check_7z_exists() -> Result<(), UploadError> {
        // 使用更可靠的方式检查7z是否存在，避免输出多余信息
        let output = Command::new("7z")
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| UploadError::SevenZipError("7z not found in PATH".into()))?;

        if output.success() {
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

        // 使用更可靠的方式调用7z，避免输出多余信息
        let output = Command::new("7z")
            .arg("a")
            .arg(format!("-v{}m", CHUNK_SIZE / (1024 * 1024)))
            .arg("-mx0")
            .arg(&output_path)
            .arg(file_path)
            .stdout(Stdio::null()) // 重定向标准输出
            .stderr(Stdio::null()) // 重定向错误输出
            .output()
            .map_err(|e| UploadError::SevenZipError(format!("Failed to execute 7z: {}", e)))?;

        if !output.status.success() {
            return Err(UploadError::SevenZipError("7z compression failed".into()));
        }

        // 查找所有分块文件
        let mut chunks = Vec::new();
        let mut part = 1;

        loop {
            // 正确的分块文件命名格式：文件名.7z.001, 文件名.7z.002, ...
            let chunk_name = format!("{}.7z.{:03}", file_stem, part);
            let chunk_path = output_dir.join(&chunk_name);
            
            if chunk_path.exists() {
                chunks.push(chunk_path);
                part += 1;
            } else {
                // 当part=1时，可能没有分块，检查单个文件是否存在（未分割的情况）
                if part == 1 {
                    let base_file = output_dir.join(format!("{}.7z", file_stem));
                    if base_file.exists() {
                        chunks.push(base_file);
                    }
                }
                break;
            }
        }

        // 如果没有任何文件，返回错误
        if chunks.is_empty() {
            return Err(UploadError::SevenZipError("No chunks created".into()));
        }

        // 输出分块信息用于调试
        println!("Created {} chunks:", chunks.len());
        for (i, chunk) in chunks.iter().enumerate() {
            println!("  Chunk {}: {}", i + 1, chunk.display());
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
    
    // 生成短文本（支持加密）
    fn generate_short_text(urls: &[String], original_file_name: &str, encrypt: bool) -> Result<String, UploadError> {
        let data = ShortTextData {
            urls: urls.to_vec(),
            original_file_name: original_file_name.to_string(),
            chunk_count: urls.len(),
            encrypted: encrypt,
        };
        
        let json = serde_json::to_string(&data)?;
        
        if encrypt {
            // 生成随机密码
            let password: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            
            // 加密数据
            let encrypted_data = Self::encrypt_data(&json, &password)?;
            
            // 返回密码和加密后的数据（Base64编码）
            Ok(format!("PASSWORD:{}|DATA:{}", password, encrypted_data))
        } else {
            // 直接返回Base64编码的数据
            Ok(general_purpose::STANDARD.encode(json))
        }
    }
    
    // 从短文本下载文件
    async fn download_from_short_text(&self, text: &str, password: Option<&str>, output_path: &str) -> Result<(), UploadError> {
        let (data, password_used) = if text.starts_with("PASSWORD:") {
            // 解析密码和加密数据
            let parts: Vec<&str> = text.splitn(2, "|DATA:").collect();
            if parts.len() != 2 {
                return Err(UploadError::Other("Invalid short text format".into()));
            }
            
            let password_part = parts[0].strip_prefix("PASSWORD:").ok_or_else(|| {
                UploadError::Other("Missing password prefix".into())
            })?;
            
            let encrypted_data = parts[1];
            
            // 使用提供的密码解密
            let decrypted_data = Self::decrypt_data(encrypted_data, password.unwrap_or(password_part))?;
            
            (decrypted_data, true)
        } else {
            // 直接解码Base64数据
            let decoded = general_purpose::STANDARD.decode(text)
                .map_err(|e| UploadError::Other(format!("Base64 decode failed: {}", e)))?;
            
            (String::from_utf8(decoded)
                .map_err(|e| UploadError::Other(format!("UTF8 conversion failed: {}", e)))?, false)
        };
        
        // 解析JSON数据
        let short_text_data: ShortTextData = serde_json::from_str(&data)?;
        
        if password_used && password.is_none() && short_text_data.encrypted {
            return Err(UploadError::Other("Password is required for encrypted short text".into()));
        }
        
        println!("Downloading {} chunks...", short_text_data.chunk_count);
        
        // 创建临时目录
        let temp_dir = tempdir()?;
        let mut chunk_paths = Vec::new();
        
        // 下载所有分块
        for (i, url) in short_text_data.urls.iter().enumerate() {
            let chunk_name = format!("chunk_{:03}", i + 1);
            let chunk_path = temp_dir.path().join(&chunk_name);
            
            println!("Downloading chunk {}/{}...", i + 1, short_text_data.chunk_count);
            self.download_file(url, &chunk_path.to_string_lossy()).await?;
            
            chunk_paths.push(chunk_path.to_string_lossy().into_owned());
        }
        
        // 合并分块
        println!("Merging chunks...");
        FileUploader::merge_chunks(output_path, &chunk_paths)?;
        
        println!("Download and merge completed: {}", output_path);
        Ok(())
    }
    
    // 加密数据
    fn encrypt_data(data: &str, password: &str) -> Result<String, UploadError> {
        // 使用AES-GCM加密
        let key = GenericArray::from_slice(password.as_bytes());
        let cipher = Aes256Gcm::new(key);
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data.as_bytes())
            .map_err(|e| UploadError::Other(format!("Encryption failed: {}", e)))?;

        // 组合nonce和密文
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);

        // Base64编码
        Ok(general_purpose::STANDARD.encode(&combined))
    }
    
    // 解密数据
    fn decrypt_data(encrypted_data: &str, password: &str) -> Result<String, UploadError> {
        // 解码Base64
        let combined = general_purpose::STANDARD.decode(encrypted_data)
            .map_err(|e| UploadError::Other(format!("Base64 decode failed: {}", e)))?;
        
        // 分离nonce和密文
        if combined.len() < 12 {
            return Err(UploadError::Other("Invalid encrypted data".into()));
        }
        
        let nonce = GenericArray::from_slice(&combined[0..12]);
        let ciphertext = &combined[12..];
        
        // 使用AES-GCM解密
        let key = GenericArray::from_slice(password.as_bytes());
        let cipher = Aes256Gcm::new(key);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| UploadError::Other(format!("Decryption failed: {}", e)))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| UploadError::Other(format!("UTF8 conversion failed: {}", e)))
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
            encrypt,
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
                    println!("\nUpload successful! Generating short text...");
                    
                    // 生成短文本
                    let short_text = FileUploader::generate_short_text(&urls, &file_name, encrypt)?;
                    
                    if encrypt {
                        // 提取密码
                        let password = short_text.split('|').next().unwrap_or("")
                            .strip_prefix("PASSWORD:").unwrap_or("");
                        
                        println!("\nEncrypted short text generated:");
                        println!("Password: {}", password);
                        println!("Short text: {}", short_text);
                        println!("\nTo download, use:");
                        println!("  program download-from-text --text \"{}\" --password {} --output-path <output-file>", short_text, password);
                    } else {
                        println!("\nShort text generated:");
                        println!("{}", short_text);
                        println!("\nTo download, use:");
                        println!("  program download-from-text --text \"{}\" --output-path <output-file>", short_text);
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
        Commands::DownloadFromText { text, password, output_path } => {
            println!("Downloading from short text...");
            uploader.download_from_short_text(&text, password.as_deref(), &output_path).await?;
            println!("\nDownload completed: {}", output_path);
        }
    }

    Ok(())
}