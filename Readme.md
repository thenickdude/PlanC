# Plan C

Code42 decided to terminate their "CrashPlan for Home" service. This means that [after the shutdown date of
October 22, 2018](https://crashplanforhome.zendesk.com/hc/en-us/articles/115000873872-Can-I-transfer-my-files-version-history-),
CrashPlan will delete your backup on their servers, which is to be expected, but much more annoyingly, you will 
*no longer be able to restore CrashPlan backups that you stored locally*. Effectively, Code42 is reaching into your 
computer to break your backups for you.

This is unacceptable to me because I'd lose the revision history for my files. Even if I was to restore a complete copy
of the newest revision of my CrashPlan archive now, if I later discover that the most recent version of one of my files 
was corrupted, I wouldn't be able to roll that file back to a previous revision. To prevent this I'd have to somehow 
restore *every* revision of *every* file from my CrashPlan archive before the shutdown, which is not feasible.

I created Plan C to solve this issue. Plan C will be able to restore files from your locally-stored CrashPlan Home backup 
even after the shutdown date. 

## Decryption keys

Code42 is able to break your backups remotely because their servers hold your backup decryption key in
escrow. When you log in to your account using the CrashPlan Home client, this key is downloaded to your computer and
stored in an encrypted form in CrashPlan's "adb" (authentication database) directory. 

After the shutdown date, you will no longer be able to log in to your account, so you will no longer be able to download 
this key. **It's possible that the CrashPlan client will erase the key automatically on this date.**

So **you should immediately make a backup copy of your adb directory** to preserve the key. First stop the CrashPlan
daemon so it releases its lock on the directory:

Windows - `net stop CrashPlanService`  
macOS - `sudo launchctl unload /Library/LaunchDaemons/com.crashplan.engine.plist`  
Linux - `sudo service crashplan stop`  
Other - https://support.code42.com/CrashPlan/4/Troubleshooting/Stop_and_start_the_Code42_app_service

Now copy the adb directory somewhere safe, here's where to find it:

Windows - `C:\ProgramData\CrashPlan\conf\adb` or `C:\Users\<username>\AppData\<Local or Roaming>\CrashPlan\conf\adb`  
macOS - `/Library/Application Support/CrashPlan/conf/adb` or `~/Library/Application Support/CrashPlan/conf/adb`  
Linux - `/usr/local/crashplan/conf/adb`  

The adb directory should contain a list of files similar to this:

```
000630.ldb
000632.ldb
000637.log
CURRENT
LOCK
LOG
MANIFEST-000636
```

It may also be useful to save CrashPlan's other files such as the `service.model` file. It's not clear what the values 
in this serialised Java object are good for, but it might come in useful for restoring backups later.

## Disclaimer

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Supported environment

Plan C is only supported on POSIX environments like macOS and Linux. Backups of Windows computers can be restored, but Plan C 
itself cannot run on Windows.

Plan C has only been tested with backups maintained with CrashPlan 4.8. Older databases may use legacy features that Plan C
does not support.

Plan C supports restoring from backup archives where the backup target was a Computer or Folder. Backups sent to Friends 
probably have additional encryption that I have not examined.

It doesn't support backups encrypted with a ["custom key"](https://support.code42.com/CrashPlan/4/Configuring/Security_Encryption_and_password_options),
but could probably be extended to do so.

It doesn't support restoring device files (sockets, etc.) or file resource forks (Mac, Windows).

It doesn't support restoring file metadata like permissions and modification times.

## Using Plan C

First use Plan C to recover your decryption key. Because of the potential for Plan C to inadvertently corrupt the adb database, it is best 
to point it to a copy of the adb directory:

```bash
plan-c --adb path/to/your/adb-copy/ recover-key 
```

The output should look like:

```
Here's your recovered decryption key (for use with --key):
47F28C8B159B44979F420A7721C3104F...
```

Now you can use that key with the `--key` argument to decrypt your backup with the other commands.

```
Options:
  --adb arg              path to CrashPlan's 'adb' directory to recover a
                         decryption key from (e.g. /Library/Application
                         Support/CrashPlan/conf/adb. Optional)
  --key arg              your backup decryption key (Hexadecimal, not your
                         password. Optional)
  --archive arg          the root of your CrashPlan backup archive
  --command arg          command to run (recover-key,list,restore,etc)

Which archived files to operate on:
  --prefix arg           prefix of the archived filepath to operate on
  --filename arg         exact archived filepath to operate on
  --include-deleted      include deleted files
  --at arg               restore/list files at the given date (yyyy-mm-dd
                         hh:mm:ss), if omitted will use the newest version

Restore options:
  --dest arg             destination directory for restored files
  --dry-run              verify integrity of restored files without actually
                         writing them to disk. Filenames are printed to stdout
                         and errors to stderr.

Commands:
  recover-key   - Recover your backup encryption key from a CrashPlan ADB directory
  list          - List all filenames that were ever in the backup (incl deleted)
  list-detailed - List the newest version of files in the backup (add --at for other times)
  list-all      - List all versions of the files in the backup
  restore       - Restore files
```

### Listing files in the backup

Use one of the `list` commands to list the contents of a CrashPlan Home backup archive.

#### List
The `list` command lists all the filenames contained in the archive, including deleted ones:

```bash
./plan-c --key 47F28C8B159... --archive crashplan-backup/29268951613 list

/Users/dave/workspace/plan-c
/Users/dave/workspace/plan-c/planc.cpp
/Users/dave/workspace/plan-c/planc.h
/Users/dave/Documents/Todo list.txt
/Users/dave/Documents/Vacation plans.txt
```

#### List detailed
The `list-detailed` command shows detailed information about the latest revision of the files in the archive:

```bash
./plan-c --key 47F28C8B159... --archive crashplan-backup/29268951613 list-detailed

/Users/dave/workspace/plan-c 0 2018-03-11 12:30:20 5D8C0210C2D84CABB3CEC8ADDE17EBF4
/Users/dave/workspace/plan-c/planc.cpp 22419 2018-03-11 12:35:33 7E26B42E73834CE1AD4B872E7F23CCA5
...
```

From left to right, the columns are the filename, the filesize (0 for directories), the time that Crashplan snapshotted 
the file, and the MD5 hash of the file (`-` for directories).

You can add `--include-deleted` to include files that no longer existed in the newest version of the backup, these are
listed with an `X` for their MD5 hash.

Add the `--at` option to show information about files in an earlier version of the backup.

#### List all
`list-all` lists every revision that Crashplan has stored for the files.
 
```bash
./plan-c --key 47F28C8B159... --archive crashplan-backup/29268951613 list-all

/Users/dave/workspace/plan-c 0 2015-05-24 02:28:09 -
/Users/dave/workspace/plan-c 0 2015-06-16 05:32:26 -
/Users/dave/workspace/plan-c 0 2017-09-14 08:11:11 -
/Users/dave/workspace/plan-c/planc.cpp 3964 2015-05-24 02:28:09 7E26B42E73834CE1AD4B872E7F23CCA5
/Users/dave/workspace/plan-c/planc.cpp 3964 2015-06-16 05:32:24 7E26B42E73834CE1AD4B872E7F23CCA5
/Users/dave/workspace/plan-c/planc.cpp 4019 2015-07-09 06:27:50 4AAE0EB528F04082B4D5DC7B59F34EA7
/Users/dave/workspace/plan-c/planc.cpp 4019 2015-07-09 21:35:09 4AAE0EB528F04082B4D5DC7B59F34EA7
/Users/dave/workspace/plan-c/planc.cpp 0 2015-09-04 15:15:08 X
/Users/dave/workspace/plan-c/planc.cpp 4144 2017-09-14 08:11:10 4CE7888DB7CA449FA729B4114B157336
...
```

### Filtering the files that are listed/restored
You can pass a `--prefix` to list or restore only files whose full path starts with a given string, e.g.:

```bash
./plan-c --key ... --archive ... --prefix /Users/dave/Documents/ list

/Users/dave/Documents/Todo list.txt
/Users/dave/Documents/Vacation plans.txt
...
```

The prefix does not pay attention to path separators, `--prefix hello` will find `hello polly.txt` and `helloworld.txt`.

To list/restore a single file, use the `--filename` option instead.
 
### Restoring files from the backup
By default, the `restore` command will restore the newest revision of every file to the destination directory.

Use the `--dest` argument to choose the directory where the restored files will be saved to. If the original file path was 
`/Users/dave/file.txt` and you set the destination to `./recovered` then the file will be restored to
`./recovered/Users/dave/file.txt`.

Use `--at` to restore an earlier snapshot of the archive.

You can use `--prefix` and `--filename` to limit the files that will be restored.

## Building Plan C

If you don't want to use one of the precompiled releases from the Releases tab above, you can build Plan C yourself. You
need a C++ compiler, make and cmake installed (e.g. `apt install build-essential make cmake` on Ubuntu Xenial).
Clone this repository, then run this command to fetch the required libraries:

```bash
git submodule update --init
``` 

Then run `make`, and all of the libraries will be built, followed by Plan C itself.