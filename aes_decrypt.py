#!/usr/bin/env python3
"""
AES文件夹解密工具
解密由aes_encrypt.py创建的加密文件夹
支持对整个文件夹进行递归解密，保持原文件名
"""
import base64
import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
from pathlib import Path

def decrypt_single_file(input_file, output_file, password, cached_keys=None):
    """
    解密单个文件
    
    Args:
        input_file: 加密文件路径
        output_file: 输出文件路径
        password: 解密密码
        cached_keys: 缓存的密钥字典（盐值->密钥）
    """
    if cached_keys is None:
        cached_keys = {}
        
    try:
        # 读取加密文件
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 检查文件格式
        if not content.startswith("AES_ENCRYPTED_FILE\n"):
            print(f"  警告: {input_file} 不是有效的AES加密文件，跳过")
            return False, 0, 0, cached_keys
        
        # 提取加密数据
        encoded_data = content.split("\n", 1)[1]
        
        # 解码数据
        try:
            combined_data = base64.b64decode(encoded_data.encode('utf-8'))
        except Exception:
            print(f"  错误: 无法解析 {input_file} 的加密数据")
            return False, 0, 0, cached_keys
        
        # 分离盐和加密内容
        if len(combined_data) < 16:
            print(f"  错误: {input_file} 的加密数据太短")
            return False, 0, 0, cached_keys
            
        salt = combined_data[:16]
        encrypted_content = combined_data[16:]
        
        # 检查是否已经缓存了这个盐值对应的密钥
        salt_key = salt.hex()
        if salt_key not in cached_keys:
            # 使用相同的密钥派生方法
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,  # 必须与加密时使用的相同
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            cached_keys[salt_key] = key
        else:
            key = cached_keys[salt_key]
        
        # 尝试解密
        f = Fernet(key)
        try:
            decrypted_data = f.decrypt(encrypted_content)
            original_content = decrypted_data.decode('utf-8')
        except Exception as e:
            if "InvalidToken" in str(e):
                print(f"  错误: 密码错误或文件已损坏 - {input_file}")
            else:
                print(f"  解密失败: {input_file} - {e}")
            return False, 0, 0, cached_keys
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # 写入解密文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(original_content)
        
        return True, len(content), len(original_content), cached_keys
        
    except Exception as e:
        print(f"  处理文件 {input_file} 时发生错误: {e}")
        return False, 0, 0, cached_keys

def decrypt_folder(encrypted_folder, output_folder, password=None):
    """
    解密整个文件夹
    
    Args:
        encrypted_folder: 加密文件夹路径
        output_folder: 输出文件夹路径
        password: 解密密码
    """
    # 检查加密文件夹是否存在
    if not os.path.exists(encrypted_folder):
        print(f"错误：加密文件夹 '{encrypted_folder}' 不存在！")
        return False
    
    if not os.path.isdir(encrypted_folder):
        print(f"错误：'{encrypted_folder}' 不是一个文件夹！")
        return False
    
    # 获取密码
    if not password:
        password = getpass.getpass("请输入解密密码: ")
    
    # 创建输出文件夹
    os.makedirs(output_folder, exist_ok=True)
    
    # 统计信息
    total_files = 0
    decrypted_files = 0
    total_encrypted_size = 0
    total_decrypted_size = 0
    failed_files = []
    cached_keys = {}  # 缓存密钥以提高性能
    
    print(f"开始解密文件夹: {encrypted_folder}")
    print(f"输出文件夹: {output_folder}")
    print("-" * 50)
    
    # 递归遍历加密文件夹
    for root, dirs, files in os.walk(encrypted_folder):
        for file in files:
            total_files += 1
            encrypted_file = os.path.join(root, file)
            
            # 计算相对路径
            relative_path = os.path.relpath(encrypted_file, encrypted_folder)
            
            # 构造输出文件路径，保持原文件名
            output_file = os.path.join(output_folder, relative_path)
            
            print(f"正在解密: {relative_path}")
            
            success, encrypted_size, decrypted_size, cached_keys = decrypt_single_file(
                encrypted_file, output_file, password, cached_keys
            )
            
            if success:
                decrypted_files += 1
                total_encrypted_size += encrypted_size
                total_decrypted_size += decrypted_size
                print(f"  ✓ 完成: {relative_path}")
            else:
                failed_files.append(relative_path)
                print(f"  ❌ 失败: {relative_path}")
    
    # 输出统计结果
    print("\n" + "=" * 50)
    print("解密完成统计:")
    print(f"  总文件数: {total_files}")
    print(f"  成功解密: {decrypted_files}")
    print(f"  失败文件: {len(failed_files)}")
    print(f"  加密文件总大小: {total_encrypted_size:,} 字符")
    print(f"  解密后总大小: {total_decrypted_size:,} 字符")
    
    if failed_files:
        print(f"\n失败的文件:")
        for file in failed_files:
            print(f"  - {file}")
    
    return len(failed_files) == 0

def main():
    if len(sys.argv) != 3:
        print("AES文件夹解密工具")
        print("使用方法: python aes_decrypt.py <加密文件夹> <输出文件夹>")
        print("示例: python aes_decrypt.py destination source")
        print("\n说明:")
        print("  - 将加密文件夹中的所有文件递归解密")
        print("  - 解密后的文件保存到输出文件夹，保持原文件名")
        print("  - 保持原有的目录结构")
        print("  - 如果输出文件夹不存在将自动创建")
        return
    
    encrypted_folder = sys.argv[1]
    output_folder = sys.argv[2]
    
    print("=" * 50)
    print("         AES-256 文件夹解密工具")
    print("=" * 50)
    
    success = decrypt_folder(encrypted_folder, output_folder)
    
    if success:
        print("\n" + "=" * 50)
        print("🎉 文件夹解密完成！文件已恢复。")
        print("=" * 50)
    else:
        print("\n❌ 文件夹解密失败！")
        sys.exit(1)

if __name__ == "__main__":
    main() 