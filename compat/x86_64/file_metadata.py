import os
import stat
import sys


def main() -> None:
    format_name, path = sys.argv[1:]
    metadata = os.stat(path)
    if format_name == "owner":
        value = f"{metadata.st_uid}:{metadata.st_gid}"
    elif format_name == "owner-mode":
        value = f"{metadata.st_uid}:{metadata.st_gid}:{metadata.st_mode & 0o7777:o}"
    elif format_name == "device-mode":
        value = f"{os.major(metadata.st_rdev):x}:{os.minor(metadata.st_rdev):x}:{stat.S_IMODE(metadata.st_mode):o}"
    elif format_name == "identity":
        value = f"{path} dev={metadata.st_dev} inode={metadata.st_ino} size={metadata.st_size}"
    else:
        raise ValueError(f"unknown metadata format: {format_name}")
    print(value)


if __name__ == "__main__":
    main()
