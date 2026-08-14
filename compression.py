import gzip
import os

SAMPLE_BYTES = 200 * 1024 * 1024  # read 200MB of compressed data as a sample

compressed_path = "CVEfixes_v1.0.8.sql.gz"
compressed_total = os.path.getsize(compressed_path)

decompressed_sample_size = 0
compressed_sample_size = 0

with open(compressed_path, "rb") as raw:
    with gzip.GzipFile(fileobj=raw) as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            decompressed_sample_size += len(chunk)
            if raw.tell() >= SAMPLE_BYTES:
                break
    compressed_sample_size = raw.tell()

ratio = decompressed_sample_size / compressed_sample_size
estimated_decompressed_total = compressed_total * ratio

print(f"Compressed file size:        {compressed_total / 1e9:.2f} GB")
print(f"Sampled compressed bytes:    {compressed_sample_size / 1e6:.1f} MB")
print(f"Sampled decompressed bytes:  {decompressed_sample_size / 1e6:.1f} MB")
print(f"Measured compression ratio:  {ratio:.2f}x")
print(f"Estimated FULL decompressed size: {estimated_decompressed_total / 1e9:.2f} GB")
print(f"Recommended free space (decompressed + ~20% SQLite overhead): "
      f"{estimated_decompressed_total * 1.2 / 1e9:.2f} GB")