#!/bin/bash

TMPDIR=${ROOT}/.tmp

function generate_common_merged_inc {
    echo > $TMPDIR/common.merged.inc.log
    COMMON_INC_MERGED_CKSUM=`stat -c %y ${ROOT}/common.inc ${ROOT}/common.overrides.*inc 2> /dev/null | xargs | sed "s/ //g"`
    if [ -f $TMPDIR/common.merged.inc ]; then
        TEST=`grep COMMON_INC_MERGED_CKSUM $TMPDIR/common.merged.inc`
        if [ "$TEST" = "`echo COMMON_INC_MERGED_CKSUM=$COMMON_INC_MERGED_CKSUM`" ]; then
             echo "script.inc: $TMPDIR/common.merged.inc is up to date" >> $TMPDIR/common.merged.inc.log
             return
        fi
    fi
    echo "COMMON_INC_MERGED_CKSUM=$COMMON_INC_MERGED_CKSUM" > $TMPDIR/common.merged.inc
    cat ${ROOT}/common.inc >> $TMPDIR/common.merged.inc

    awk 'FNR==1{ print ""}{print}' ${ROOT}/common.overrides.*inc 2> /dev/null > $TMPDIR/common.overrides.inc
    cat $TMPDIR/common.overrides.inc | grep '^[^# ]*=' | while read line; do
        original_key=`echo $line | awk -F= '{ print $1; }'`
        original_value=`echo $line | sed "s/^${original_key}=//g" | sed "s/\"//g"`
        if [ "`echo $original_key | cut -c ${#original_key}`" == "+" ]; then
            # we need to append to the the original value (if any)
            key=`echo $original_key | cut -c 1-$(( ${#original_key} - 1 ))`
            old_value=`grep ^${key}= $TMPDIR/common.merged.inc | sed "s/^${key}=//g" | sed "s/\"//g"`
            if [ "$old_value" != "" ]; then
                value="$old_value $original_value"
                # eliminate duplicate arguments
                value=$(echo $value | tr ' ' '\n' | sed 's/^-Wl,-plugin-opt=-load=/-Wl,-plugin-aopt=-load=/' | sort -u | sed 's/^-Wl,-plugin-aopt=-load=/-Wl,-plugin-opt=-load=/' | tr '\n' ' ')
            else
                value=$original_value
            fi
        else
            key=$original_key
            value=$original_value
        fi
        if grep -q ^${key}= $TMPDIR/common.merged.inc; then
            value=`echo $value | sed "s/\\\//\\\\\\\\\//g"`
            sed -i "s/^${key}=.*/${key}=\"${value}\"/g" $TMPDIR/common.merged.inc
            echo "script.inc: Overriding common.inc using `cat $TMPDIR/common.overrides.inc | grep ^${original_key}=`" >> $TMPDIR/common.merged.inc.log
        else
            echo "${key}=\"${value}\"" >> $TMPDIR/common.merged.inc
            echo "script.inc: Extending common.inc using `cat $TMPDIR/common.overrides.inc | grep ^${original_key}=`" >> $TMPDIR/common.merged.inc.log
        fi
    done
    append_env_vars $TMPDIR/common.merged.inc
}

function append_env_vars
{
    if [ "$(uname -m)" == "x86_64" ]; then
        ARCH_NAME=x64
        ARCH_BITS=64
    else
        ARCH_NAME=x86
        ARCH_BITS=32
    fi

    echo "ARCH_NAME=$ARCH_NAME" >> $1
    echo "ARCH_BITS=$ARCH_BITS" >> $1
}

generate_common_merged_inc

. $TMPDIR/common.merged.inc

if [ $HAVE_LLVM -eq 1 ]; then
    LLVM_VERSION=`$LLVMPREFIX/bin/llvm-config --version | sed "s/[^0-9]//g"`
else
    LLVM_VERSION=0
fi
