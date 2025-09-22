#!/bin/bash
function info(){
    echo -e "\033[34m\033[01mℹ️ $1\033[0m"  # 蓝色信息，带ℹ️图标
}
function success(){
    echo -e "\033[32m\033[01m✅ $1\033[0m"  # 绿色成功，带✅图标
}
function error(){
    echo -e "\033[31m\033[01m❌ $1\033[0m"  # 红色错误，带❌图标
}
function warning(){
    echo -e "\033[33m\033[01m⚠️ $1\033[0m"  # 黄色警告，带⚠️图标
}
