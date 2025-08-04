#!/usr/bin/env python3
"""
AES文件夹加密工具
使用AES-256加密算法和PBKDF2密钥派生
支持对整个文件夹进行递归加密，保持原文件名
"""
import base64
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
from pathlib import Path

def encrypt_single_file(input_file, output_file, password, salt, key):
    """
    加密单个文件
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        password: 加密密码
        salt: 盐值
        key: 加密密钥
    """
    try:
        # 读取原文件内容
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 创建Fernet对象并加密内容
        f = Fernet(key)
        encrypted_data = f.encrypt(content.encode('utf-8'))
        
        # 将盐和加密数据组合并编码
        combined_data = salt + encrypted_data
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        
        # 添加标识头
        final_content = f"AES_ENCRYPTED_FILE\n{encoded_data}"
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # 写入加密文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(final_content)
        
        return True, len(content), len(final_content)
        
    except Exception as e:
        print(f"加密文件 {input_file} 失败: {e}")
        return False, 0, 0

def encrypt_folder(source_folder, destination_folder, password=None):
    """
    加密整个文件夹
    
    Args:
        source_folder: 源文件夹路径
        destination_folder: 目标文件夹路径
        password: 加密密码
    """
    # 检查源文件夹是否存在
    if not os.path.exists(source_folder):
        print(f"错误：源文件夹 '{source_folder}' 不存在！")
        return False
    
    if not os.path.isdir(source_folder):
        print(f"错误：'{source_folder}' 不是一个文件夹！")
        return False
    
    # 获取密码
    if not password:
        password = getpass.getpass("请输入加密密码: ")
        confirm_password = getpass.getpass("请再次输入密码确认: ")
        if password != confirm_password:
            print("错误：两次输入的密码不一致！")
            return False
    
    # 创建目标文件夹
    os.makedirs(destination_folder, exist_ok=True)
    
    # 生成随机盐（16字节）- 整个文件夹使用同一个盐
    salt = os.urandom(16)
    
    # 使用PBKDF2从密码派生32字节密钥
    print("正在生成加密密钥...")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # 10万次迭代，增强安全性
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    
    # 统计信息
    total_files = 0
    encrypted_files = 0
    total_original_size = 0
    total_encrypted_size = 0
    failed_files = []
    
    print(f"开始加密文件夹: {source_folder}")
    print(f"目标文件夹: {destination_folder}")
    print("-" * 50)
    
    # 递归遍历源文件夹
    for root, dirs, files in os.walk(source_folder):
        for file in files:
            total_files += 1
            source_file = os.path.join(root, file)
            
            # 计算相对路径
            relative_path = os.path.relpath(source_file, source_folder)
            
            # 构造目标文件路径，保持原文件名
            destination_file = os.path.join(destination_folder, relative_path)
            
            print(f"正在加密: {relative_path}")
            
            success, original_size, encrypted_size = encrypt_single_file(
                source_file, destination_file, password, salt, key
            )
            
            if success:
                encrypted_files += 1
                total_original_size += original_size
                total_encrypted_size += encrypted_size
                print(f"  ✓ 完成: {relative_path}")
            else:
                failed_files.append(relative_path)
                print(f"  ❌ 失败: {relative_path}")
    
    # 输出统计结果
    print("\n" + "=" * 50)
    print("加密完成统计:")
    print(f"  总文件数: {total_files}")
    print(f"  成功加密: {encrypted_files}")
    print(f"  失败文件: {len(failed_files)}")
    print(f"  原始总大小: {total_original_size:,} 字符")
    print(f"  加密后总大小: {total_encrypted_size:,} 字符")
    
    if failed_files:
        print(f"\n失败的文件:")
        for file in failed_files:
            print(f"  - {file}")
    
    return len(failed_files) == 0

def main():
    if len(sys.argv) != 3:
        print("AES文件夹加密工具")
        print("使用方法: python aes_encrypt.py <源文件夹> <目标文件夹>")
        print("示例: python aes_encrypt.py source destination")
        print("\n说明:")
        print("  - 将源文件夹中的所有文件递归加密")
        print("  - 加密后的文件保存到目标文件夹，保持原文件名")
        print("  - 保持原有的目录结构")
        print("  - 如果目标文件夹不存在将自动创建")
        return
    
    source_folder = sys.argv[1]
    destination_folder = sys.argv[2]
    
    print("=" * 50)
    print("         AES-256 文件夹加密工具")
    print("=" * 50)
    
    success = encrypt_folder(source_folder, destination_folder)
    
    if success:
        print("\n" + "=" * 50)
        print("🎉 文件夹加密完成！请妥善保管您的密码。")
        print("使用 aes_decrypt.py 可以解密文件夹。")
        print("=" * 50)
    else:
        print("\n❌ 文件夹加密失败！")
        sys.exit(1)

if __name__ == "__main__":
    main() 