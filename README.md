# Hg.SecureShellSync

Allow to synchronize databases using SFTP (FTP over SSH)

The sftp connection info are store using a standard entry in the database.

Features:
- sync on open
- sync on save
- perdioc sync on timer


# How to use

Edit the entry named "Hg.SecureShellSync" and set following fields:
- username
- password
- url with the following format:

sftp://<ip or domain>[:port]/[path/to/db/]

Note that "path/to/db/" is the path to the folder where the db will be sync, the original name of the db will be use.

The entry itself can be rename or moved as long as you don't change its Uuid.


# About

This is a (very) long overdue upload.


## Background 

Back in mid 2012 I started to use KeePass and since I was going to use it both at home and at work, often at the same time via remote access (VNC), I needed a way to sync the database with merge.

I looked around the plugins page and tried a few of them but nothing was doing exactly what I wanted. Keep in mind that Cloud sync service were not popular and widely used and at the time I didn't had a Dropbox or any other service like that.

What I had, and still have, is a dedicated server to host various websites and other services.



## Creation

I tried the plugin [KeepPassSync](https://sourceforge.net/projects/keepasssync/) and used its sources as a tutorial on how to make a plugin and as a base to start my own.

I had originally implemented synchronization using pure ssh, scp and sftp but I never used anything else than sftp myself and dropped all the code related to ssh and scp over the years (and to be honest pure ssh support was somewhat dubious).

I had my first working version by the end of 2012.


## Improvements

After the basic sync on open and/or save feature, I added a one other feature requested by my brother, the only other user.

Sync on open and save was enough for me because I'm using the save on lock feature and locking when Idle / locking when Windows is locked.


This was not working for my brother because at his work he have to lock his computer many times per day and he was getting tired of typing back two password each time (one for Windows and one for KeePass), so he didn't used the locking option of KeePass.

And since the database wasn't getting locked, it wasn't saved and not sync often. So I added the ability to sync periodically.

Over the few next year I mostly fixed few bugs and improved the sync process and error reporting.



## Now (as of January 2021)

My last update was around 2017 with a bump of SSH.NET to version 2016.

This project has been moving from computer to computer and has never been in any verson control system and I almost lost it because of this.

So after 8 years, I think it is long overdue to properly manage it using a proper SCM and and share it.

