//! Owned conventional local account databases.
//!
//! [`UserDatabase`] and [`GroupDatabase`] parse immutable, caller-owned
//! snapshots of `/etc/passwd` and `/etc/group`. Their `from_system` methods
//! obtain those snapshots through crabc's direct Linux file boundary. Every
//! field is owned, lookup is source-order deterministic, and there is no C
//! static result buffer, process-global enumeration cursor, NSS lookup, or
//! provider plug-in involved.
//!
//! Lines are strict UTF-8 and reject interior NUL bytes. Blank and comment
//! lines are ignored; all other lines must have the conventional field count
//! and representable numeric identifiers. Repeated names or identifiers are
//! retained for source-order enumeration, and a lookup returns the first such
//! record just as a linear local-file lookup does. System snapshots are capped
//! at one mebibyte so an unbounded administrator-controlled file cannot force
//! unbounded native allocation.

use alloc::string::String;
use alloc::vec::Vec;

use crate::process::{Gid, Uid};

/// Errors from parsing or loading a conventional local account database.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DatabaseError {
    /// A non-empty record has invalid text, fields, or numeric identifiers.
    InvalidInput,
    /// A system snapshot exceeds the bounded native representation.
    Overflow,
    /// Direct opening or reading of the conventional local file failed.
    System(crate::Errno),
}

/// An owned conventional `/etc/passwd` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    name: String,
    password: String,
    uid: Uid,
    gid: Gid,
    gecos: String,
    home: String,
    shell: String,
}

impl User {
    /// Returns the login name exactly as recorded in the local file.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }

    /// Returns the password field, which is normally a placeholder such as `x`.
    #[must_use]
    pub fn password(&self) -> &str { &self.password }

    /// Returns the numeric user identifier.
    #[must_use]
    pub const fn uid(&self) -> Uid { self.uid }

    /// Returns the primary numeric group identifier.
    #[must_use]
    pub const fn gid(&self) -> Gid { self.gid }

    /// Returns the GECOS field exactly as recorded.
    #[must_use]
    pub fn gecos(&self) -> &str { &self.gecos }

    /// Returns the recorded home directory spelling.
    #[must_use]
    pub fn home(&self) -> &str { &self.home }

    /// Returns the recorded login-shell spelling.
    #[must_use]
    pub fn shell(&self) -> &str { &self.shell }
}

/// An immutable, source-order `/etc/passwd` snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserDatabase {
    entries: Vec<User>,
}

impl UserDatabase {
    /// Parses a caller-owned `/etc/passwd` snapshot.
    pub fn from_bytes(input: &[u8]) -> core::result::Result<Self, DatabaseError> {
        let mut entries = Vec::new();
        for line in input.split(|&byte| byte == b'\n') {
            let line = without_line_ending(line);
            if ignorable(line) { continue; }
            let fields = split_exact(line, 7)?;
            entries.push(User {
                name: required_text(fields[0])?,
                password: text(fields[1])?,
                uid: Uid::from_raw(identifier(fields[2])?),
                gid: Gid::from_raw(identifier(fields[3])?),
                gecos: text(fields[4])?,
                home: text(fields[5])?,
                shell: text(fields[6])?,
            });
        }
        Ok(Self { entries })
    }

    /// Loads and parses `/etc/passwd` through direct Linux descriptor I/O.
    pub fn from_system() -> core::result::Result<Self, DatabaseError> {
        Self::from_bytes(&read_system_file(b"/etc/passwd")?)
    }

    /// Returns the first source-order record with this exact login name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&User> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Returns the first source-order record with this numeric user ID.
    #[must_use]
    pub fn by_uid(&self, uid: Uid) -> Option<&User> {
        self.entries.iter().find(|entry| entry.uid == uid)
    }

    /// Returns records in source order, including duplicate identifiers.
    #[must_use]
    pub fn entries(&self) -> &[User] { &self.entries }

    /// Returns whether this snapshot contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Returns the number of source records.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Iterates over records in source order.
    pub fn iter(&self) -> core::slice::Iter<'_, User> { self.entries.iter() }
}

impl<'a> IntoIterator for &'a UserDatabase {
    type Item = &'a User;
    type IntoIter = core::slice::Iter<'a, User>;

    fn into_iter(self) -> Self::IntoIter { self.entries.iter() }
}

/// An owned conventional `/etc/group` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    name: String,
    password: String,
    gid: Gid,
    members: Vec<String>,
}

impl Group {
    /// Returns the group name exactly as recorded.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }

    /// Returns the password field, which is normally a placeholder such as `x`.
    #[must_use]
    pub fn password(&self) -> &str { &self.password }

    /// Returns the numeric group ID.
    #[must_use]
    pub const fn gid(&self) -> Gid { self.gid }

    /// Returns member login names in the file's comma-separated order.
    #[must_use]
    pub fn members(&self) -> &[String] { &self.members }
}

/// An immutable, source-order `/etc/group` snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GroupDatabase {
    entries: Vec<Group>,
}

impl GroupDatabase {
    /// Parses a caller-owned `/etc/group` snapshot.
    pub fn from_bytes(input: &[u8]) -> core::result::Result<Self, DatabaseError> {
        let mut entries = Vec::new();
        for line in input.split(|&byte| byte == b'\n') {
            let line = without_line_ending(line);
            if ignorable(line) { continue; }
            let fields = split_exact(line, 4)?;
            entries.push(Group {
                name: required_text(fields[0])?,
                password: text(fields[1])?,
                gid: Gid::from_raw(identifier(fields[2])?),
                members: members(fields[3])?,
            });
        }
        Ok(Self { entries })
    }

    /// Loads and parses `/etc/group` through direct Linux descriptor I/O.
    pub fn from_system() -> core::result::Result<Self, DatabaseError> {
        Self::from_bytes(&read_system_file(b"/etc/group")?)
    }

    /// Returns the first source-order record with this exact group name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Group> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Returns the first source-order record with this numeric group ID.
    #[must_use]
    pub fn by_gid(&self, gid: Gid) -> Option<&Group> {
        self.entries.iter().find(|entry| entry.gid == gid)
    }

    /// Returns records in source order, including duplicate identifiers.
    #[must_use]
    pub fn entries(&self) -> &[Group] { &self.entries }

    /// Returns whether this snapshot contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Returns the number of source records.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Iterates over records in source order.
    pub fn iter(&self) -> core::slice::Iter<'_, Group> { self.entries.iter() }
}

impl<'a> IntoIterator for &'a GroupDatabase {
    type Item = &'a Group;
    type IntoIter = core::slice::Iter<'a, Group>;

    fn into_iter(self) -> Self::IntoIter { self.entries.iter() }
}

/// The two conventional local account-file snapshots acquired together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Database {
    users: UserDatabase,
    groups: GroupDatabase,
}

impl Database {
    /// Parses independently supplied passwd and group snapshots.
    pub fn from_bytes(
        passwd: &[u8],
        group: &[u8],
    ) -> core::result::Result<Self, DatabaseError> {
        Ok(Self {
            users: UserDatabase::from_bytes(passwd)?,
            groups: GroupDatabase::from_bytes(group)?,
        })
    }

    /// Loads `/etc/passwd` and `/etc/group` as separate immutable snapshots.
    ///
    /// The files are intentionally not treated as an atomic multi-file
    /// transaction; administrators may replace either file between reads.
    pub fn from_system() -> core::result::Result<Self, DatabaseError> {
        Ok(Self {
            users: UserDatabase::from_system()?,
            groups: GroupDatabase::from_system()?,
        })
    }

    /// Returns the owned passwd snapshot.
    #[must_use]
    pub const fn users(&self) -> &UserDatabase { &self.users }

    /// Returns the owned group snapshot.
    #[must_use]
    pub const fn groups(&self) -> &GroupDatabase { &self.groups }
}

fn without_line_ending(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn ignorable(line: &[u8]) -> bool {
    line.is_empty() || line.first() == Some(&b'#')
}

fn split_exact<'a>(line: &'a [u8], expected: usize) -> core::result::Result<Vec<&'a [u8]>, DatabaseError> {
    let fields: Vec<_> = line.split(|&byte| byte == b':').collect();
    if fields.len() == expected { Ok(fields) } else { Err(DatabaseError::InvalidInput) }
}

fn required_text(value: &[u8]) -> core::result::Result<String, DatabaseError> {
    if value.is_empty() { Err(DatabaseError::InvalidInput) } else { text(value) }
}

fn text(value: &[u8]) -> core::result::Result<String, DatabaseError> {
    if value.contains(&0) { return Err(DatabaseError::InvalidInput); }
    String::from_utf8(value.to_vec()).map_err(|_| DatabaseError::InvalidInput)
}

fn identifier(value: &[u8]) -> core::result::Result<u32, DatabaseError> {
    if value.is_empty() { return Err(DatabaseError::InvalidInput); }
    let mut result = 0u64;
    for &byte in value {
        if !byte.is_ascii_digit() { return Err(DatabaseError::InvalidInput); }
        result = result
            .checked_mul(10)
            .and_then(|number| number.checked_add((byte - b'0') as u64))
            .ok_or(DatabaseError::Overflow)?;
    }
    u32::try_from(result).map_err(|_| DatabaseError::Overflow)
}

fn members(value: &[u8]) -> core::result::Result<Vec<String>, DatabaseError> {
    if value.is_empty() { return Ok(Vec::new()); }
    value.split(|&byte| byte == b',').map(required_text).collect()
}

const MAX_SYSTEM_FILE_BYTES: usize = 1024 * 1024;

fn read_system_file(path: &[u8]) -> core::result::Result<Vec<u8>, DatabaseError> {
    let descriptor = crate::fs::open(path, crate::fs::OFlags::CLOEXEC, crate::fs::Mode::empty())
        .map_err(DatabaseError::System)?;
    let mut snapshot = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match crabc_core::io::read(descriptor.as_raw_fd(), &mut chunk) {
            Ok(read) => read,
            Err(crate::Errno::INTR) => continue,
            Err(error) => return Err(DatabaseError::System(error)),
        };
        if read == 0 { break; }
        let new_length = snapshot.len().checked_add(read).ok_or(DatabaseError::Overflow)?;
        if new_length > MAX_SYSTEM_FILE_BYTES { return Err(DatabaseError::Overflow); }
        snapshot.extend_from_slice(&chunk[..read]);
    }
    Ok(snapshot)
}
