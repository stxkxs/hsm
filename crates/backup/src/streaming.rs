//! Streaming backup support for large datasets.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{BackupError, Result};

/// Header for streaming backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingBackupHeader {
    /// Version of the streaming format
    pub version: u32,
    /// Total number of keys (if known)
    pub total_keys: Option<usize>,
    /// Timestamp
    pub timestamp: i64,
    /// Compression enabled
    pub compressed: bool,
}

impl StreamingBackupHeader {
    /// Create a new streaming backup header
    pub fn new(total_keys: Option<usize>, compressed: bool) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            version: 1,
            total_keys,
            timestamp,
            compressed,
        }
    }
}

/// Streaming backup writer
pub struct StreamingBackupWriter<W: AsyncWrite + Unpin> {
    writer: W,
    keys_written: usize,
}

impl<W: AsyncWrite + Unpin> StreamingBackupWriter<W> {
    /// Create a new streaming backup writer
    pub async fn new(mut writer: W, header: StreamingBackupHeader) -> Result<Self> {
        // Write header
        let header_bytes = postcard::to_allocvec(&header)
            .map_err(|e| BackupError::Serialization(e.to_string()))?;

        // Write header length
        writer.write_u32(header_bytes.len() as u32).await?;

        // Write header
        writer.write_all(&header_bytes).await?;
        writer.flush().await?;

        Ok(Self {
            writer,
            keys_written: 0,
        })
    }

    /// Write a key to the stream
    pub async fn write_key(&mut self, key_id: &str, key_data: &[u8]) -> Result<()> {
        // Serialize key
        let key_entry = (key_id, key_data);
        let key_bytes = postcard::to_allocvec(&key_entry)
            .map_err(|e| BackupError::Serialization(e.to_string()))?;

        // Write key length
        self.writer.write_u64(key_bytes.len() as u64).await?;

        // Write key data
        self.writer.write_all(&key_bytes).await?;

        self.keys_written += 1;
        Ok(())
    }

    /// Finish writing and flush
    pub async fn finish(mut self) -> Result<usize> {
        // Write end marker (zero length)
        self.writer.write_u64(0).await?;
        self.writer.flush().await?;

        Ok(self.keys_written)
    }

    /// Get number of keys written
    pub fn keys_written(&self) -> usize {
        self.keys_written
    }
}

/// Streaming backup reader
pub struct StreamingBackupReader<R: AsyncRead + Unpin> {
    reader: R,
    keys_read: usize,
    header: StreamingBackupHeader,
}

impl<R: AsyncRead + Unpin> StreamingBackupReader<R> {
    /// Create a new streaming backup reader
    pub async fn new(mut reader: R) -> Result<Self> {
        // Read header length
        let header_len = reader.read_u32().await? as usize;

        // Read header
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes).await?;

        let header: StreamingBackupHeader = postcard::from_bytes(&header_bytes)
            .map_err(|e| BackupError::Deserialization(e.to_string()))?;

        Ok(Self {
            reader,
            keys_read: 0,
            header,
        })
    }

    /// Read the next key from the stream
    pub async fn read_key(&mut self) -> Result<Option<(String, Vec<u8>)>> {
        // Read key length
        let key_len = self.reader.read_u64().await? as usize;

        // Zero length indicates end of stream
        if key_len == 0 {
            return Ok(None);
        }

        // Read key data
        let mut key_bytes = vec![0u8; key_len];
        self.reader.read_exact(&mut key_bytes).await?;

        // Deserialize key
        let (key_id, key_data): (String, Vec<u8>) = postcard::from_bytes(&key_bytes)
            .map_err(|e| BackupError::Deserialization(e.to_string()))?;

        self.keys_read += 1;
        Ok(Some((key_id, key_data)))
    }

    /// Get the header
    pub fn header(&self) -> &StreamingBackupHeader {
        &self.header
    }

    /// Get number of keys read
    pub fn keys_read(&self) -> usize {
        self.keys_read
    }

    /// Read all remaining keys
    pub async fn read_all(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut keys = Vec::new();

        while let Some(key) = self.read_key().await? {
            keys.push(key);
        }

        Ok(keys)
    }
}

/// Write a streaming backup to a file
pub async fn write_streaming_backup_to_file(
    path: &Path,
    keys: Vec<(String, Vec<u8>)>,
    compressed: bool,
) -> Result<usize> {
    let file = tokio::fs::File::create(path).await?;
    let writer = tokio::io::BufWriter::new(file);

    let header = StreamingBackupHeader::new(Some(keys.len()), compressed);
    let mut backup_writer = StreamingBackupWriter::new(writer, header).await?;

    for (key_id, key_data) in keys {
        backup_writer.write_key(&key_id, &key_data).await?;
    }

    backup_writer.finish().await
}

/// Read a streaming backup from a file
pub async fn read_streaming_backup_from_file(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let file = tokio::fs::File::open(path).await?;
    let reader = tokio::io::BufReader::new(file);

    let mut backup_reader = StreamingBackupReader::new(reader).await?;
    backup_reader.read_all().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_streaming_write_read() {
        let mut buffer = Vec::new();

        // Write
        {
            let header = StreamingBackupHeader::new(Some(3), false);
            let mut writer = StreamingBackupWriter::new(&mut buffer, header)
                .await
                .unwrap();

            writer.write_key("key1", b"data1").await.unwrap();
            writer.write_key("key2", b"data2").await.unwrap();
            writer.write_key("key3", b"data3").await.unwrap();

            let count = writer.finish().await.unwrap();
            assert_eq!(count, 3);
        }

        // Read
        {
            let cursor = Cursor::new(buffer);
            let mut reader = StreamingBackupReader::new(cursor).await.unwrap();

            assert_eq!(reader.header().total_keys, Some(3));

            let key1 = reader.read_key().await.unwrap().unwrap();
            assert_eq!(key1.0, "key1");
            assert_eq!(key1.1, b"data1");

            let key2 = reader.read_key().await.unwrap().unwrap();
            assert_eq!(key2.0, "key2");

            let key3 = reader.read_key().await.unwrap().unwrap();
            assert_eq!(key3.0, "key3");

            let end = reader.read_key().await.unwrap();
            assert!(end.is_none());

            assert_eq!(reader.keys_read(), 3);
        }
    }

    #[tokio::test]
    async fn test_streaming_read_all() {
        let mut buffer = Vec::new();

        // Write
        {
            let header = StreamingBackupHeader::new(Some(2), false);
            let mut writer = StreamingBackupWriter::new(&mut buffer, header)
                .await
                .unwrap();

            writer.write_key("key1", b"data1").await.unwrap();
            writer.write_key("key2", b"data2").await.unwrap();

            writer.finish().await.unwrap();
        }

        // Read all
        {
            let cursor = Cursor::new(buffer);
            let mut reader = StreamingBackupReader::new(cursor).await.unwrap();

            let keys = reader.read_all().await.unwrap();
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0].0, "key1");
            assert_eq!(keys[1].0, "key2");
        }
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let mut buffer = Vec::new();

        // Write empty stream
        {
            let header = StreamingBackupHeader::new(Some(0), false);
            let writer = StreamingBackupWriter::new(&mut buffer, header)
                .await
                .unwrap();
            let count = writer.finish().await.unwrap();
            assert_eq!(count, 0);
        }

        // Read empty stream
        {
            let cursor = Cursor::new(buffer);
            let mut reader = StreamingBackupReader::new(cursor).await.unwrap();

            let key = reader.read_key().await.unwrap();
            assert!(key.is_none());
        }
    }

    #[tokio::test]
    async fn test_large_keys() {
        let mut buffer = Vec::new();

        // Write large key
        {
            let header = StreamingBackupHeader::new(Some(1), false);
            let mut writer = StreamingBackupWriter::new(&mut buffer, header)
                .await
                .unwrap();

            let large_data = vec![0xAB; 1024 * 1024]; // 1 MB
            writer.write_key("large_key", &large_data).await.unwrap();

            writer.finish().await.unwrap();
        }

        // Read large key
        {
            let cursor = Cursor::new(buffer);
            let mut reader = StreamingBackupReader::new(cursor).await.unwrap();

            let key = reader.read_key().await.unwrap().unwrap();
            assert_eq!(key.0, "large_key");
            assert_eq!(key.1.len(), 1024 * 1024);
            assert_eq!(key.1[0], 0xAB);
        }
    }

    #[tokio::test]
    async fn test_header_metadata() {
        let mut buffer = Vec::new();

        let header = StreamingBackupHeader::new(Some(5), true);
        assert_eq!(header.version, 1);
        assert_eq!(header.total_keys, Some(5));
        assert!(header.compressed);

        let writer = StreamingBackupWriter::new(&mut buffer, header)
            .await
            .unwrap();
        writer.finish().await.unwrap();

        let cursor = Cursor::new(buffer);
        let reader = StreamingBackupReader::new(cursor).await.unwrap();

        assert_eq!(reader.header().version, 1);
        assert_eq!(reader.header().total_keys, Some(5));
        assert!(reader.header().compressed);
    }

    #[tokio::test]
    async fn test_file_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_backup.stream");

        // Write to file
        let keys = vec![
            ("key1".to_string(), b"data1".to_vec()),
            ("key2".to_string(), b"data2".to_vec()),
            ("key3".to_string(), b"data3".to_vec()),
        ];

        let count = write_streaming_backup_to_file(&file_path, keys.clone(), false)
            .await
            .unwrap();
        assert_eq!(count, 3);

        // Read from file
        let read_keys = read_streaming_backup_from_file(&file_path).await.unwrap();
        assert_eq!(read_keys.len(), 3);
        assert_eq!(read_keys, keys);
    }
}
