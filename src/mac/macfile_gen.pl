#!/usr/athena/bin/perl -w

if (defined ($ENV{'KERBSRCROOT'}))
{
	$ROOT=$ENV{'KERBSRCROOT'};
} else {
	$ROOT='.';
}

print(STDERR "Creating makefile.\n");

@MACLIST=&make_macfile_maclist(&make_macfile_list());
@MACSRCS=grep(/\.c$/, @MACLIST);
@MACSRCSK5=grep($_!~/:gssapi:/, @MACSRCS);
@MACSRCSGSS=grep($_=~/:gssapi:/, @MACSRCS);

$MAKEFILE=&chew_on_filename("Makefile");
&delete_file("Makefile") && print(STDERR "Old makefile ($MAKEFILE) deleted.\n");
open(MF, ">".&chew_on_filename("Makefile")) || die "Can't open Makefile for writing";
print(MF "SRCS = ", join(" ", @MACSRCS), "\n\n");
@MFSRCD=grep(s/(.*:)[^:]*\.c$/$1/, &copy_array(@MACLIST));
@MFSRCD=&uniq(sort(@MFSRCD));
print(MF "SRCDIRS =  @MFSRCD\n\n");

@MACSRCSGSS=grep(s/.*://, @MACSRCSGSS);
@MACSRCSK5=grep(s/.*://, @MACSRCSK5);

for $A (0..2)
{
	@ARCH=('68K', '68K', '68K') if $A==0;
	@ARCH=('68KCFM', 'CFM68', 'CFM-68K') if $A==1;
	@ARCH=('PPC', 'PPC', 'PPC') if $A==2;

	print MF "GSSOBJS$ARCH[0] = ";
	for $SRC (@MACSRCSGSS)
	{
		print(MF ":bin:$ARCH[2]:$SRC.$ARCH[1].o ");
	}
	print(MF "\n\n");

	print MF "K5OBJS$ARCH[0] = ";
	for $SRC (@MACSRCSK5)
	{
		print(MF ":bin:$ARCH[2]:$SRC.$ARCH[1].o ");
	}
	print(MF "\n\n");
}

@HEADERS=grep(s/(.*:)[^:]*\.h$/ -i $1/, @MACLIST);
print(MF "AUTOINCLUDES = ", &uniq(sort(@HEADERS)), "\n");

print(MF "\n#  TEMPLATE BEGINS HERE\n\n");

@TEMPLATE=&read_file("mac/Makefile.tmpl");
$TEMPLATE=join("\n", @TEMPLATE)."\n";
$TEMPLATE=~tr#\*/:\\#\245:\304\266#;
print MF $TEMPLATE;

print(STDERR "$MAKEFILE successfully generated.\n");
exit;

# Assuming the arguments are sorted, returns a copy with all duppliactes
# removed.
# @SPARSE_LIST = &uniq(@DUP_LIST);
sub uniq
{
	if (@_==0) { return (); }
	if (@_==1) { return @_; }
	local($N);
	for ($N=0; $N<$#_; $N++)
	{
		$_[$N]=undef if $_[$N] eq $_[$N+1];
	}
	return(grep(defined($_), @_));
}

# Makes a makefile line-list from a list of sources.
# @MACFILE_MACLIST = &make_macfile_maclist(@SOURCE_FILES);
sub make_macfile_maclist
{
	local(@LINES)=@_;
	local($I);
	for $I (0..$#LINES)
	{
		$LINES[$I]=~s|/|:|g;
		$LINES[$I]=~s|^|:|g;
		if ($LINES[$I]=~/:.:/) { $LINES[$I]=undef; }
		elsif ($LINES[$I]=~/:mac:/) { $LINES[$I]=undef; }
	}
	grep(defined($_), @LINES);
}

# Returns a list of files needed in the mac build.
# @FILES = &make_macfile_list ();
sub make_macfile_list
{
	local(@MAKEFILE)=&merge_continue_lines(&read_file("Makefile.in"));
	local($MACDIRS)=&extract_variable("MAC_SUBDIRS", @MAKEFILE);
	local(@RETVAL)=&macfiles_sh(split(/\s+/, $MACDIRS));

	local(@MACFILES)=split(/\s+/, &extract_variable("MACFILES", @MAKEFILE));
	local(@FOUND)=();
	local($MACFILE);
	for $MACFILE (@MACFILES)
	{
		push(@FOUND, &find_and_glob($MACFILE));
	}

	push(@RETVAL, &sed_exclude("config/winexclude.sed", @FOUND));
	@RETVAL;
}

# Applies SEDFILE to STREAM.  Only deletions are valid.
# This could be expanded if neccessary.
# @OUT = &sed_exclude($SEDFILE, @STREAM);
sub sed_exclude
{
	if ($#_<1)
	{
		print STDERR "Invalid call to sed_exclude.\n";
		exit(1);
		# I have this error because it always indicates
		# that something is wrong, not because a one argument
		# call doesn't make sense.
	}
	local ($SEDFILE, @STREAM)=($_[0], @_[1..$#_]);
	local (@SEDLINES)=&read_file($SEDFILE);
	local (@DELLINES)=grep(s#^/(.*)/d$#$1#, @SEDLINES);
	if (@SEDLINES!=@DELLINES)
	{
		print STDERR "sed script $SEDFILE confused me.\n";
		exit(1);
	}
	local ($LINE, @RETVALS);
	@RETVALS=();
	for $LINE (@STREAM)
	{
		local($RET)=(1);
		for $DEL (@DELLINES)
		{
			if ($LINE=~/$DEL/)
			{
				$RET=0;
			}
		}
		$RET && push(@RETVALS, $LINE);
	}
	@RETVALS;
}

# Returns a list of files that match a glob.  You can only glob in the
# filename part...no directories allowed.  Only real files (no dirs,
# block specials, etc.) are returned.  An example argument is
# "./vers?filesfoo*.c".  ?'s and *'s are valid globbing characters.  You
# can push your luck with []'s, but it is untested.  Files must be visible.
# @FILES = &find_and_glob("$BASEDIR/$FILEGLOB");
sub find_and_glob
{
	local($PATTERN)=($_[0]);
	local($DIR, $FILE)=($PATTERN=~m|^(.*)/([^/]*)$|)[0,1];
	if (!defined($FILE) || !defined($DIR) || length($DIR)<1 || length($FILE)<1)
	{	
		print STDERR "Invalid call to find_and_glob.\n";
		exit(1);
	}
	$FILE=~s/\./\\\./g;
	$FILE=~s/\*/\.\*/g;
	$FILE=~s/\?/./g;
	local (@FILES)=&list_in_dir($DIR, $FILE);
	local (@RETVAL)=();
	for (@FILES)
	{
		push(@RETVAL, "$DIR/$_");
	}
	@RETVAL;
}

# Recurses over @DIRS and returns a list of files needed for the mac krb5
# build.  It is similar to the macfiles.sh script.
# @MACFILES = &macfiles_sh(@DIRS);
sub macfiles_sh
{
	local (@RETVAL)=();
	local ($DIR);
	for $DIR (@_)
	{
		local (@MAKEFILE);
		@MAKEFILE=&merge_continue_lines(&read_file("$DIR/Makefile.in"));
		for $SDIR (split(/\s+/, &extract_variable("MAC_SUBDIRS", @MAKEFILE)))
		{
			local(@MAKEFILE)=&merge_continue_lines(
			                   &read_file("$DIR/$SDIR/Makefile.in"));
			local(@SRCS)=(split(/\s+/, (&extract_variable('MACSRCS', @MAKEFILE) .
			                            &extract_variable('MACSRC', @MAKEFILE) .
			                            &extract_variable('SRCS', @MAKEFILE) .
			                            &extract_variable('SRC', @MAKEFILE))));
			@SRCS=grep(/.*\.c/, @SRCS);
			local ($SRC);
			for $SRC (@SRCS)
			{
				$SRC=~s|.*/([^/]+)|$1|;
				push(@RETVAL, "$DIR/$SDIR/$SRC");
			}
			local(@HEADS)=&list_in_dir("$DIR/$SDIR", '.*\.h$');
			local($HEAD);
			for $HEAD (@HEADS)
			{
				push(@RETVAL, "$DIR/$SDIR/$HEAD");
			}
			push(@RETVAL, &macfiles_sh("$DIR/$SDIR"));
		}
	}
	@RETVAL;
}
exit;

# Given a the contents of a makefile in @_[1,$#_], one line to an element,
# returns the Makefile format variable specified in $_[0].  If the
# $FILE_NAME variable is defined, it is used in error messages.
# @MAKEFILE_CONTENTS should have already been filtered through
# merge_continue_lines().
# $VARIABLE_VALUE = &extract_variable($VARAIBLE_NAME, @MAKEFILE_CONTENTS);
sub extract_variable
{
	local ($FN, $VARNAME, @LINES, @MATCHES);
	$FN=defined($FILE_NAME)?$FILE_NAME:"<unknown>";
	
	if ($#_<2)
	{
		print(STDERR "Invalid call to extract_variable.\n");
		exit(1);
	}
	$VARNAME=$_[0];
	@LINES=@_[1..$#_];
	@MATCHES=grep(/^$VARNAME\s*=.+/, @LINES);
	if (@MATCHES>1)
	{
		print STDERR "Too many matches for variable $VARNAME in $FN.\n";
		exit(1);
	}
	if (@MATCHES==0)
	{
		return "";
	}
	return ($MATCHES[0]=~/^$VARNAME\s*=\s*(.*)$/)[0];
}

# Print the arguments separated by newlines.
# &print_lines(@LINES);
sub print_lines
{
	print(join("\n", @_), "\n");
}

# Given an array of lines, returns the same array transformed to have
# all lines ending in backslashes merged with the following lines.
# @LINES = &merge_continue_lines(@RAWLINES);
sub merge_continue_lines
{
	local ($LONG)=join("\n", @_);
	$LONG=~s/\\\n/ /g;
	return split('\n', $LONG);
}

# Returns the contents of the file named $_[0] in an array, one line
# in each element.  Newlines are stripped.
# @FILE_CONTENTS = &read_file($FILENAME);
sub read_file
{
	die("Bad call to read_file") unless defined $_[0];
	local($FN) = (&chew_on_filename($_[0]));
	local (@LINES, @NLFREE_LINES);

	if (!open(FILE, $FN))
	{
		print(STDERR "Can't open $FN.\n");
		exit(1);
	}

	@LINES=<FILE>;
	@NLFREE_LINES=grep(s/\n$//, @LINES);
	
	if (!close(FILE))
	{
		print(STDERR "Can't close $FN.\n");
		exit(1);
	}

	@NLFREE_LINES;
}

# lists files that match $PATTERN in $DIR.
# Returned files must be real, visible files.
# @FILES = &list_in_dir($DIR, $PATTERN);
sub list_in_dir
{
	local ($DIR, $PATTERN) = @_[0,1];
	local ($MACDIR)=&chew_on_filename($DIR);
	opendir(DIRH, $MACDIR) || die("Can't open $DIR");
	local(@FILES)=readdir(DIRH);
	closedir(DIRH);
	local (@RET)=();
	for (@FILES)
	{
		local($FILE)=$_;
		if ($FILE=~/^$PATTERN$/ && &is_a_file("$DIR/$_") && $FILE=~/^[^.]/)
		{
			push(@RET, $FILE);
		}
	}
	@RET;
}

# Returns whether the argument exists and is a real file.
# $BOOL = &is_a_file($FILENAME);
sub is_a_file
{
	die("Invalid call to is_a_file()") unless defined($_[0]);
	local($FILE)=$_[0];
	return -f &chew_on_filename($FILE);
}

# Returns the argument, interpretted as a filename, munged
# for the local "Operating System", as defined by $^O.
# As of now, fails on full pathnames.
# $LOCALFN = &chew_on_filename($UNIXFN);
sub chew_on_filename
{
	if (@_!=1)
	{
		print(STDERR "Bad call to chew_on_filename.\n");
		exit(1);
	}
	$_=$_[0];

	$_="$ROOT/$_";
	
	if ($^O eq 'MacOS')
	{
		s%/\.\./%:/%g;
		s%^\.\./%/%;
		s%^\./%%;
		s%/\./%/%g;
		s%/\.$%%g;
		s%/%:%g;
		s%^%:%g;
		s%^:\.$%:%;
	}

	return $_;
}

# Deletes a file
# &delete_file($FILE);
sub delete_file
{
	die("Illegal call to delete_file()") unless defined $_[0];
	unlink(&chew_on_filename($_[0]));
}

# Returns a one-level deep copy of an array.
# @B = &copy_array(@A);
sub copy_array
{
	local (@A)=();
	for (@_)
	{
		push(@A, $_);
	}
	@A;
}

