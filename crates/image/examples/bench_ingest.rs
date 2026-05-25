use std::env;
use std::time::Instant;

use microsandbox_image::{
    filetree::ResourceLimits,
    tar_ingest::{Compression, ingest_compressed_tar},
};
use tokio::io::AsyncWriteExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mb: usize = env::args().nth(1).unwrap_or_else(|| "50".into()).parse()?;
    let split: usize = env::args().nth(2).unwrap_or_else(|| "1".into()).parse()?;
    eprintln!("Generating tar.gz with {} files of {} MB each", split, mb);
    let per_file_bytes = mb * 1024 * 1024;

    // Build a tar.gz in memory
    let tar_gz_bytes = {
        use std::io::Write;
        let mut tar_buf = Vec::with_capacity(per_file_bytes * split + 1024 * split);
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for i in 0..split {
                // Random data for incompressibility
                let mut data = vec![0u8; per_file_bytes];
                // Use fast PRNG instead of /dev/urandom
                let mut state: u64 = 0x1234_5678_u64.wrapping_add(i as u64);
                for chunk in data.chunks_mut(8) {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let bytes = state.to_le_bytes();
                    let n = chunk.len();
                    chunk.copy_from_slice(&bytes[..n]);
                }
                let mut hdr = tar::Header::new_gnu();
                hdr.set_path(format!("payload_{}.bin", i))?;
                hdr.set_size(per_file_bytes as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                builder.append(&hdr, &data[..])?;
            }
            builder.finish()?;
        }
        // gzip-compress
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf)?;
        gz.finish()?
    };
    eprintln!(
        "tar.gz size = {} bytes ({:.2} MB)",
        tar_gz_bytes.len(),
        tar_gz_bytes.len() as f64 / 1048576.0
    );

    // Write to a temp file (mimics the on-disk path)
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();
    {
        let mut f = tokio::fs::File::create(&path).await?;
        f.write_all(&tar_gz_bytes).await?;
        f.flush().await?;
    }
    let reader = tokio::fs::File::open(&path).await?;

    let spool_dir = tempfile::tempdir()?;
    let spool_path = spool_dir.path().join("test.spool");

    let limits = ResourceLimits {
        max_total_size: u64::MAX / 4,
        max_file_size: u64::MAX / 4,
        max_entry_count: u64::MAX / 4,
        max_path_length: 4096,
        max_path_depth: 1024,
        max_symlink_target: 4096,
    };

    let started = Instant::now();
    let result =
        ingest_compressed_tar(reader, Compression::Gzip, &limits, Some(&spool_path)).await?;
    let elapsed = started.elapsed();

    eprintln!(
        "ingest_compressed_tar: {} files * {} MB = {} MB total -> {} ms ({:.1} MB/s)",
        split,
        mb,
        mb * split,
        elapsed.as_millis(),
        (mb * split) as f64 * 1000.0 / elapsed.as_millis() as f64
    );
    eprintln!("uncompressed_digest = {}", result.uncompressed_digest);
    Ok(())
}
