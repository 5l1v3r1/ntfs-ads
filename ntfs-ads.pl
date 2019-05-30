#!/usr/bin/perl -w
########################################################
#
#    NTFS Streams Manipulation Tool
#
#    Version 0.2
#
#    This script is intended to reveal, list, delete, show contents,
#    extract/copy hidden files from NTFS Alternate Data Streams.
#
#    This script requires perl, zenity, ntfs-3g, attr
#
#    If you have errors: look at the bottom lines of this script for solutions
#
###############################################################################
#
#    Copyright (C) 2008 by Pavel Prostine
#    Bug reports to: sven7@users.sourceforge.net
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
###############################################################################

use strict;

######## check prerequisites before start GUI ##########
# check permission: need to be root for mount
die "need to be root\n" if $> ne 0;

my @prerequisites = qw/ ntfs-3g zenity getfattr/;
foreach (@prerequisites) {
    system("which $_ 2>&1 >/dev/null");
    die "$_ is not installed" if $? ne 0;
}

######## add some ntfs specific magic numbers ###############################
# read more http://sedna-soft.de/summary-information-stream/
# read www.sandersonforensics.com/Files/ZoneIdentifier.pdf
my $magic = <<EOF;
0	string	\\xfe\\xff\\x00\\x00\\x05\\x00\\x02\\x00\\x00	NTFS stream Metadata Win 5.0 (W2k)
0	string	\\xfe\\xff\\x00\\x00\\x05\\x01\\x02\\x00\\x00	NTFS stream Metadata Win 5.1 (XP)
0	string	\\xfe\\xff\\x00\\x00\\x05\\x02\\x02\\x00\\x00	NTFS stream Metadata Win x64/2003
0	string	\\xfe\\xff\\x00\\x00\\x06\\x00\\x02\\x00\\x00	NTFS stream Metadata Win Vista/2008
0	string	\\xfe\\xff\\x00\\x00				NTFS stream Metadata
0	string	[ZoneTransfer]\\x0d\\x0aZoneId=3		NTFS stream Zone.Identifier 3 (Internet) WinXP SP2 and above
0	string	[ZoneTransfer]					NTFS stream Zone.Identifier WinXP SP2 and above
EOF

# TODO: add check for md5sum of .magic file and rewrite it (ask confirmation) if old version
if ( !-e "$ENV{HOME}/.magic" ) {
    open( MAGIC, ">$ENV{HOME}/.magic" ) or die "cannot open \$HOME/.magic $ENV{HOME} : $!";
    print MAGIC $magic;
    close MAGIC;
}

#######################################################
my %ads;    # main hash (of hashes), store all information, construction:

# $ads = {
# 	   '/dev/sda1'=>{
# 	      'size' => 'unknown',
# 	      'mounted' => 'no,
# 	      'streams' => {
# 		'file1.txt' => {
#			'bad.exe' => {
#				'size' => 7654,
#				'filetype' => 'executable',
#				'atime' => '1893432234',      # unixtime
#				'mtime' => '1457824393'
#				}
#			},
# 		'file2.rtf' => {             # <- this file has more then one stream
#			'Zone.Identifier'=> {
#				'size' => 7654,
#				'filetype' => 'executable'
#				},
#			'lala.exe'=> {
#				'size' => 7654,
#				'filetype' => 'executable'
#				},
#			'bubu.exe'=> {
#				'size' => 7654,
#				'filetype' => 'executable'
#				},
#			},
# 		'/windows/system32' => {	# streams can attach to folders too
#			'hidden.exe'=>{
#				'size' => 7654,
#				'filetype' => 'executable'
#				},
# 		},
# };
# how to add a stream :
# $ads{/dev/sda1}->{'streams'}->{'file2.rtf'}->{$stream_name}->{'size'}='unknown';

# run and parse fdisk to find any ntfs partitions
fdisk_find_ntfs_partitions_and_calculate_size();

die "no ntfs partitions found\n" if scalar keys %ads == 0;

check_if_already_mounted();

my @zenity;    # text for zenity (GUI) dialog
foreach ( keys %ads ) {
    push @zenity, "TRUE", $_, $ads{$_}->{size} . "GB", $ads{$_}->{mounted};
}

my @partitions_to_proceed = zenity_list( "zenity". # zenity command
	" --title 'Choose NTFS partitons to proceed' --list --checklist ".
	" --text='Choose NTFS partitions to proceed.\nClose all open files on mounted NTFS partitions' ".
	" --column  'Proceed?'  --column  'Partition'  --column 'Size' --column 'Mounted' ".
	"@zenity --width=500 --height=300" );

#######################
### collect information about streams
## DONE: mount -o noatime,nodiratime to avoid changing atime
## mount -o sync,dirsync
## TODO: mount -F (works w/o fstab?) fork off a new incarnation of mount for each device (w.about partition?) - can speed up mounting

foreach my $partition (@partitions_to_proceed) {
    my $mountpoint = '';    # create own unique mountpoint for every ntfs partition
    if ( $partition =~ /\/dev\/([hs]d[a-z]\d+)/i ) {
        $mountpoint = '/mnt_' . $1;    # if busy? create uniq mountpoint like mnt_hda1
        if ( !-d $mountpoint ) {       #create folder $mountpoint if not exists
            mkdir($mountpoint) or die "cannot mkdir $mountpoint: $!";
        }
    } else {
        die "mess with mountpoint $mountpoint\n";
    };
    if ( $ads{$partition}->{mounted} eq 'yes' ) {
        umount_partition($partition);
        #sync_and_sleep(1); # no needed after umount if block device and at least kernel 2.6.20
    }
    mount_partition( $partition, $mountpoint, "-o ro,noatime,nodiratime,streams_interface=xattr" );
    sync_and_sleep(1);
    parse_getfattr( $partition, $mountpoint );
    sync_and_sleep(1);
    umount_partition($partition);
    #sync_and_sleep(1); # no needed after umount if block device and at least kernel 2.6.20
    mount_partition( $partition, $mountpoint, " -o noatime,nodiratime,streams_interface=windows " );
    get_filetype_and_size($partition);
}

# list of all found ads
@zenity = "";    #clear
foreach my $partition ( keys(%ads) ) {
    foreach my $file ( keys %{ $ads{$partition}->{'streams'} } ) {
        foreach my $stream ( keys %{ $ads{$partition}->{'streams'}->{$file} } ) {
            my $filetype = $ads{$partition}->{'streams'}->{$file}->{$stream}->{'filetype'} || "unknown";
            my $size     = $ads{$partition}->{'streams'}->{$file}->{$stream}->{'size'};
            my $atime    = $ads{$partition}->{'streams'}->{$file}->{$stream}->{'atime'};
            my $mtime    = $ads{$partition}->{'streams'}->{$file}->{$stream}->{'mtime'};
            ## all entries containing blanks should be enclosed in \"
            push @zenity, "TRUE \"$partition/$file:$stream\" $size \"$filetype\" \"" . &gettime($mtime) . "\" \"" . &gettime($atime) . "\"";
        }
    }
}

# ask wich file should be extracted
my @ads_to_extract = zenity_list( "zenity --title 'Choose NTFS streams to extract' --list --checklist ".
	" --text='Choose NTFS stream to extract.\nAll choosed streams will be extracted and copied in saved_ntfs_streams folder.\n'".
	"'You can delete all or only desired streams in next step.\n'".
	"'Click OK to extract choosed streams or CANCEL to jump to delete dialog without extracting.' ".
" --column  'Extract?'  --column  'Drive File Stream'  --column 'Size, B' --column 'File type' --column 'Last modified' --column 'Last access' ".
	" @zenity --width=1000 --height=400" );

### extracting ads
if ( scalar @ads_to_extract > 0 && !-d "saved_ntfs_streams" ) {
    mkdir("saved_ntfs_streams");    # create folder only if we have something to extract
}
foreach (@ads_to_extract) {
    print "to extract      : $_\n";
    if (/\/dev\/([hs]d[a-z]\d+)\/(.+):(.+)/) {
        my ( $mountpoint, $file, $stream ) = ( "/mnt_" . $1, $2, $3 );
        # change to:
        # (my $file = $2) =~ s| |\\ |g;
        $file   =~ s| |\\ |g;
        $stream =~ s| |\\ |g;
        # new names for storing extracted streams
        my ( $mountpointSave, $fileSave, $streamSave ) = ( $mountpoint, $file, $stream );    #
        $mountpointSave =~ s/\W/_/g;
        $fileSave       =~ s/\W/_/g;
        $streamSave     =~ s/\W/_/g;
        print "to extract parsed: $mountpoint/$file:$stream\n";
        system("cp --force $mountpoint/$file:$stream saved_ntfs_streams/$mountpointSave-$fileSave---$streamSave");
    }
}

## now delete ads
my @ads_to_delete = zenity_list( "zenity --title 'Choose NTFS streams to delete' --list --checklist ".
	"--text='Choose NTFS streams to delete.\nClick OK to delete choosed streams or CANCEL to exit the program.' ".
" --column  'Delete?'  --column  'Drive File Stream'  --column 'Size, B' --column 'File type' --column 'Last modified' --column 'Last access' ".
	" @zenity --width=1000 --height=400" );

### delete ads
foreach (@ads_to_delete) {
    print "to delete      : $_\n";
    if (/\/dev\/([hs]d[a-z]\d+)\/(.+):(.+)/) {
        my ( $mountpoint, $file, $stream ) = ( "/mnt_" . $1, $2, $3 );
        $file   =~ s| |\\ |g;
        $stream =~ s| |\\ |g;
        print "to delete parsed: $mountpoint/$file:$stream\n";
        system("rm $mountpoint/$file:$stream");    # or die "cannot rm $mountpoint/$file:$stream: $! $?";
    }
}

# are there ntfs partitions? if yes then calculate size of partition (1GB=1024Bytes * 1024 * 1024)
# 1GiB = 1000 Bytes * 1000 * 1000
sub fdisk_find_ntfs_partitions_and_calculate_size {
    open( FDISK, "LANG=C LC_ALL=C fdisk -l | " ) or die "open FDISK failed $!";
    my ( $current_drive, $heads, $sectors, $sector_size, $current_partition, $partition_start, $partition_end, $partition_size ) = undef;
    while (<FDISK>) {
        if (/^Disk (\/dev\/[hs]d[a-z]):/) {
            $current_drive = $1;
            print "current drive: " . $current_drive . " ";
        } elsif (/(\d+) heads, (\d+) sectors\/track, \d+ cylinders/) {
            ( $heads, $sectors ) = ( $1, $2 );
            print "(heads: $heads, sectors: $sectors, ";
        } elsif (/Units = cylinders of \d+ \* (\d+)/) {
            $sector_size = $1;
            print "sector size: $sector_size bytes)\n";
        } elsif (/(\/dev\/[hs]d[a-z]\d+)\s+\*?\s*(\d+)\s+(\d+).*ntfs/i) {
            ( $current_partition, $partition_start, $partition_end ) = ( $1, $2, $3 );
            print "NTFS partition: $current_partition starts: $partition_start ends: $partition_end  ";
            #now we check if we have all information to calculate size of partition
            if ( ( $current_partition =~ m/$current_drive\d+/ ) && $heads && $sectors && $sector_size && $partition_start && $partition_end ) {
                $partition_size = sprintf( "%.2f", ( $heads * $sectors * $sector_size * ( $partition_end - $partition_start ) / 1024 / 1024 / 1024 ) );
                print ", size: " . $partition_size . " GB\n";
                $ads{$current_partition} = { 'size' => $partition_size, 'mounted' => 'no' };
            }
            else {
                $ads{$current_partition} = { 'size' => 'unknown ', 'mounted' => 'no' };
                print ", size unknown ???\n";
            }
        }
    } # no }else{ here!! its OK
    close FDISK;
}

# already mounted?
# TODO try with /proc/mounts
sub check_if_already_mounted {
    open( MOUNT, "mount | " ) or die "open MOUNT failed $!";
    while (<MOUNT>) {
        foreach my $ntfs_partition ( keys %ads ) {
            if (/$ntfs_partition/) {
                print "$ntfs_partition already mounted $_";
                $ads{$ntfs_partition}->{'mounted'} = 'yes';
            }
        }
    }
    close MOUNT;
}

## umount partition and check if failed
sub umount_partition {
    print "umounting $_[0]\n";
    open( UMOUNT, "umount $_[0] |" ) or die "umount of $_[0] failed $!";
    #TODO: check if fail!!
    #die "(<UMOUNT>)" if scalar(<UMOUNT>) == 0;
    close UMOUNT;
}

## mount partition and check if failed
sub mount_partition {
    my ( $partition, $mountpoint, @arguments ) = @_;
    print "mounting $partition on $mountpoint @arguments\n";
    open( MOUNT, "mount -t ntfs-3g $partition $mountpoint @arguments |" ) or die "mount $partition on $mountpoint @arguments $!";
    close MOUNT;
}

### get data from zenity output, and return parsed @
sub zenity_list {
    my @return = ();
    open( ZENITY, "@_ |" );
    foreach ( split /\|/, (<ZENITY>) ) {
        chomp;
        push @return, $_;
    }
    return @return;
}

### convert unixtime from atime/mtime to human format
sub gettime($) {
    my @t = localtime( $_[0] );
    return sprintf( "%02d:%02d:%02d %04d/%02d/%02d", $t[2], $t[1], $t[0], $t[5] + 1900, $t[4] + 1, $t[3] );
}

#### parse output of getfattr command
sub parse_getfattr {
    my ( $partition, $mountpoint ) = @_;
    print "getfattr $partition on $mountpoint\n";
    open( GETFATTR, "getfattr -R --absolute-names $mountpoint | " ) or die "open GETFATTR failed $!";
    my $current_file;
    my $file_number = 1;
    foreach (<GETFATTR>) {
        #print "processing line: $_\n";
        if (/# file: \/mnt_[hs]d[a-z]\d+\/(.*)/i) {
            $current_file = $1;    # FIXME
            $current_file =~ s/\\(\d\d\d)/chr(oct($1))/eg;    # /e to execute right part ##########
        } elsif (/^\n/) {  # skip empty lines
            #print "\\n\n";
        } elsif (/^user\.(.*)$/) {
            #print "ADS: ".$_;
            my $current_ads = $1;
            $current_ads =~ s/\\(\d\d\d)/chr(oct($1))/eg;     # /e to execute right part ###########
            $ads{$partition}->{'streams'}->{$current_file}->{$current_ads}->{'size'} = "unknown";
        } else {
            die "######### unknown string $_\n";
        }
    }
    close GETFATTR;
}

sub get_filetype_and_size ($) {
    my $partition  = $_[0];
    my $mountpoint = '';
    if ( $partition =~ /\/dev\/([hs]d[a-z]\d+)/i ) {
        $mountpoint = '/mnt_' . $1;
    } else {
        die "cannot set mountpoint: $!";
    };
    foreach my $file ( keys %{ $ads{$partition}->{'streams'} } ) {
        foreach my $stream ( keys %{ $ads{$partition}->{'streams'}->{$file} } ) {
            my $file1   = $file;
            my $stream1 = $stream;
            $file1   =~ s/ /\\ /g;
            $stream1 =~ s/ /\\ /g;
            open( FILETYPE, "file -b -m $ENV{HOME}/.magic:/usr/share/file/magic $mountpoint/$file1:$stream1 2>&1 | " );
            my $filetype = <FILETYPE>;
            chomp($filetype);
            print "$partition $file $stream $filetype\n";
            $ads{$partition}->{'streams'}->{$file}->{$stream}->{'filetype'} = "$filetype";
            my @stat = stat("$mountpoint/$file:$stream");    # TODO: check !!
            $ads{$partition}->{'streams'}->{$file}->{$stream}->{'size'}  = $stat[7];
            $ads{$partition}->{'streams'}->{$file}->{$stream}->{'atime'} = $stat[8];
            $ads{$partition}->{'streams'}->{$file}->{$stream}->{'mtime'} = $stat[10];
        }
    }
}

# we need to run this sub to avoid error like:
# umount: /dev/Data: device is busy
# or/and
# fuse mount failed: Device or resource busy
sub sync_and_sleep {
    open( SYNC, "sync |" );
    close SYNC;
    sleep( $_[0] );
}

############################################
###########################################
####### ERRORS ###########################
#
## sh: Syntax error: "(" unexpected
## it means shell got something like that (ord(45)) as parameter
## the perl didnt execute some operation and pass it further to shell: to zenity or file etc
#
##
# umount: /dev/Data: device is busy
# fuse mount failed: Device or resource busy
# SOLUTION: try to increase sleep time argument in sync_and_sleep(n);
