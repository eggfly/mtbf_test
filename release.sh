#!/bin/sh
set -e

is_darwin=0;
uname_output=`uname`
echo "uname=$uname_output"
if [ "$uname_output" = "Darwin" ];then
	is_darwin=1
else
	is_darwin=0
fi

# remind the commiter to bump the version number
current_path=`pwd`
echo 'working dir='$current_path
version_file=$current_path/version.txt
mtbf_script_file=$current_path/mtbf_preparation.py
lines=`cat $version_file`
lines=($lines)
previous_version_number=${lines[0]}
previous_md5_checksum=${lines[1]}

echo "previous version:"
echo $previous_version_number
echo $previous_md5_checksum
echo ""

prefix="version="
previous_version_str=${previous_version_number#*$prefix}

# bash support only integers, so we have to use awk as instead
new_version=`echo $previous_version_str | awk {'print $0+0.01'}`
# cp $mtbf_script_file "$mtbf_script_file.bak"
from_str='__script_version = '$previous_version_str
to_str='__script_version = '$new_version
# actually replace the line
echo $mtbf_script_file
sed -i "_bak" "s/$from_str/$to_str/g" ./mtbf_preparation.py
echo "bump version from $previous_version_str to $new_version"
# re-add it to stage
git add ./mtbf_preparation.py

current_md5=""
if [ $is_darwin -eq 1 ];then
	md5=`md5 -q $mtbf_script_file`
else
	md5=`md5sum $mtbf_script_file`
fi
md5="md5=$md5"
new_version="version=$new_version"
echo ""
echo 'current version:'
echo $new_version
echo $md5

echo $new_version > ./version.txt
echo $md5 >> ./version.txt
git add ./version.txt

git commit -m "bump version to $new_version"
git push origin master



