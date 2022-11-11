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

CrashPlan Home:

Windows - `net stop CrashPlanService`
macOS - `sudo launchctl unload /Library/LaunchDaemons/com.crashplan.engine.plist`
Linux - `sudo service crashplan stop`  

CrashPlan Small Business:

Windows - `net stop "Code42 Service"`
macOS - `sudo launchctl unload /Library/LaunchDaemons/com.code42.service.plist`
Linux - `sudo service crashplan stop`  
Other - https://support.code42.com/Incydr/Agent/Troubleshooting/Stop_and_start_the_Code42_app_service

Now copy the adb directory somewhere safe, here's where to find it:

Windows - `C:\ProgramData\CrashPlan\conf\adb` or `C:\Users\<username>\AppData\<Local or Roaming>\CrashPlan\conf\adb`  
macOS - `/Library/Application Support/CrashPlan/conf/adb` or `~/Library/Application Support/CrashPlan/conf/adb`  
Linux - `/usr/local/crashplan/conf/adb`  

On Windows, files in the conf directory are owned by SYSTEM, so a regular user can't open or copy them without first taking ownership of them.

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

Plan C has only been tested with backups maintained with CrashPlan 4.8. Older databases may use legacy features that Plan C
does not support.

Plan C supports restoring from backup archives where the backup target was a Computer or Folder. Backups sent to Friends 
probably have additional encryption that I have not examined.

It doesn't support restoring device files (sockets, etc.) or file resource forks (Mac, Windows).

It doesn't support restoring file metadata like permissions.

## Using Plan C

### Recovering your decryption key

First you must use Plan C to recover your decryption key. 

#### Recovery from ADB - CrashPlan Home

Your decryption key is stored in CrashPlan's adb database. Because of the potential for Plan C to inadvertently corrupt 
the adb database, it is best to point it to a copy of the adb directory:

```bash
plan-c --adb path/to/your/adb-copy/ recover-key 
```

The output should look like:

```
Here's your recovered decryption key (for use with --key):
47F28C8B159B44979F420A7721C3104F...
```

#### Recovery from ADB - CrashPlan Small Business

In this version, the adb directory is encrypted using a key that is specific to the computer that CrashPlan was 
installed on (so key recovery must be run on that computer).

Currently, Plan C only supports adb directories created on Windows.

On Windows, the adb directory is encrypted by the "Local System" account, so we need to use a tool called "PsExec" to 
run Plan C as Local System. Download it from here and put PsExec.exe into the same directory as Plan C:

https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

Now press the start button and type "cmd". Right click on "command prompt" and click "run as administrator". Change into
the Plan C directory and run: 

    psexec.exe -c -s plan-c.exe recover-key --adb c:\your\copy\of\adb

Replace the pathname with the full path to a copy of the adb directory. 

#### Recovery from a passphrase

If you had Crashplan generate a key for you based on a passphrase, you can use the `derive-key` command instead to 
re-derive that key:

```
# ./plan-c derive-key

Enter your Crashplan user ID (a number, can be found in conf/my.service.xml or in log files, grep for "userId"), or press enter if you don't know it:
? 123

Enter your passphrase:
? Hello World!

Here's your recovered decryption key (for use with --key):
35577843654F79774C6F424731755A46493D3A4D54497A7074677373784E5465444E42656A6E46445672596C6E69454C386F3D3A4D54497A
```

If you don't know your user ID, you can just press enter at that prompt and a brute-force search will be used to guess
your user ID instead. You also need to provide the --cpproperties argument which points to the cp.properties file in your
backup archive:

```
./plan-c derive-key --cpproperties 32141451345134/cp.properties

Enter your Crashplan user ID (a number, can be found in conf/my.service.xml or in log files, grep for "userId"), or press enter if you don't know it:
?

Since you didn't provide a userid, it will be recovered using a brute-force search instead

Enter your passphrase:
? Hello World!

Brute-forcing your userID now (up to a maximum of #100,000)... expect this to take up to 5-10 minutes
Recovered user ID: 123
Here's your recovered decryption key (for use with --key):
35577843654F79774C6F424731755A46493D3A4D54497A7074677373784E5465444E42656A6E46445672596C6E69454C386F3D3A4D54497A
```

#### Recovery from cp.properties

In some CrashPlan installs, an archive key can be found in the "secureDataKey" field of a `cp.properties` file.
If you have one of these files that contains this field, you can recover the key like so:

```
# ./plan-c recover-key --cpproperties cp.properties

The secureDataKey field in cp.properties is encrypted with your CrashPlan Account Password or Archive Password. Enter that password now to attempt decryption of the key:
? helloworld

Here's your recovered decryption key (for use with --key):
634F4F6259636F44773D3A4D54497A4E413D3D4F6458674E53415130646C6833524D78634675396C443970546A343D3A4D54497A4E413D3D
```

#### Custom 76-character decryption key
If you have a Crashplan custom encryption key which is a 76-character long Base64 string, use the `--key64` argument to 
supply it directly to Plan C.

### Calling Plan C

Now you can use your recovered key with the `--key` argument to decrypt your backup with the other commands.

```
Options:
  --adb arg              path to CrashPlan's 'adb' directory to recover a
                         decryption key from (e.g. /Library/Application
                         Support/CrashPlan/conf/adb. Optional)
  --cpproperties arg     path to a cp.properties file containing a
                         'secureDataKey' field to recover a decryption key from
                         (Optional)
  --max-userid           maximum user ID to consider when performing a brute-force
                         search with derive-key (default 10000000)
  --key arg              your backup decryption key (Hexadecimal, not your
                         password. Optional)
  --key64 arg            backup decryption key in base64 (76 characters long)                       
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
  derive-key    - Derive an encryption key from an archive password
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

/Users/dave/workspace/plan-c 0 2018-03-11 12:30:20 2018-03-10 15:31:37 5D8C0210C2D84CABB3CEC8ADDE17EBF4
/Users/dave/workspace/plan-c/planc.cpp 22419 2018-03-11 12:35:33 2018-03-10 15:32:45 7E26B42E73834CE1AD4B872E7F23CCA5
...
```

From left to right, the columns are the filename, the filesize (0 for directories), the time that Crashplan snapshotted 
the file, the file's last modification timestamp, and the MD5 hash of the file (`-` for directories).

You can add `--include-deleted` to include files that no longer existed in the newest version of the backup, these are
listed with an `X` for their MD5 hash.

Add the `--at` option to show information about files in an earlier version of the backup.

#### List all
`list-all` lists every revision that Crashplan has stored for the files.
 
```bash
./plan-c --key 47F28C8B159... --archive crashplan-backup/29268951613 list-all

/Users/dave/workspace/plan-c 0 2015-05-24 02:28:09 2015-05-23 17:04:23 -
/Users/dave/workspace/plan-c 0 2015-06-16 05:32:26 2015-05-23 17:04:23 -
/Users/dave/workspace/plan-c 0 2017-09-14 08:11:11 2015-05-23 17:04:23 -
/Users/dave/workspace/plan-c/planc.cpp 3964 2015-05-24 02:28:09 2015-05-23 17:06:28 7E26B42E73834CE1AD4B872E7F23CCA5
/Users/dave/workspace/plan-c/planc.cpp 3964 2015-06-16 05:32:24 2015-05-23 17:06:28 7E26B42E73834CE1AD4B872E7F23CCA5
/Users/dave/workspace/plan-c/planc.cpp 4019 2015-07-09 06:27:50 2015-07-08 11:23:52 4AAE0EB528F04082B4D5DC7B59F34EA7
/Users/dave/workspace/plan-c/planc.cpp 4019 2015-07-09 21:35:09 2015-07-08 11:23:52 4AAE0EB528F04082B4D5DC7B59F34EA7
/Users/dave/workspace/plan-c/planc.cpp 0 2015-09-04 15:15:08 2015-09-04 15:15:08 X
/Users/dave/workspace/plan-c/planc.cpp 4144 2017-09-14 08:11:10 2017-09-13 16:07:54 4CE7888DB7CA449FA729B4114B157336
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

## Troubleshooting

If you receive an error like this:

    Failed to open block manifest (cpbf0000000000008341334/cpbmf) for reading: Too many open files

This is triggered by `ulimit`'s file descriptor limits. Remove the open file handle limit before running Plan C like so: 

    ulimit -n unlimited    

## Building Plan C

If you don't want to use one of the precompiled releases from the Releases tab above, you can build Plan C yourself. You
need a C++ compiler, make and cmake installed (e.g. `apt install build-essential make cmake git` on Ubuntu Xenial).
Clone this repository, then run `make`, and all of the libraries will be fetched and built, followed by Plan C itself.

On Windows, build Plan C using [Msys2](https://www.msys2.org/)'s UCRT64 environment, and install these packages:

```
pacman -S git mingw-w64-ucrt-x86_64-{make,cmake,ninja,gcc}
```