#!/usr/bin/env python3
"""
NIST 테스트 벡터를 바이너리 포맷으로 변환

Usage:
    python nist_to_tvec.py input.txt output.bin

Input Format (NIST SP 800-38D style):
    [ENCRYPT]
    Count = 0
    Key = cafebabe...
    IV = cafebabe...
    PT = d9313225...
    AAD = feedface...
    CT = 42831ec2...
    Tag = 5bc94fbc...
"""

import struct
import sys
import re
import os

ALGORITHMS = {'AES': 0, 'ARIA': 1, 'SEED': 2}
MODES = {'ECB': 0, 'CBC': 1, 'CFB': 2, 'OFB': 3, 'CTR': 4, 'GCM': 5}

def detect_mode_from_filename(filename):
    """파일명에서 모드 감지"""
    basename = os.path.basename(filename).lower()
    for mode in MODES.keys():
        if mode.lower() in basename:
            return mode
    return 'GCM'  # 기본값

def parse_nist_gcm(filename):
    """NIST GCM 테스트 벡터 파일 파싱"""
    vectors = []
    current_vector = {}
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            
            # 주석 및 빈 줄 무시
            if not line or line.startswith('#'):
                continue
            
            # 섹션 헤더 무시
            if line.startswith('['):
                continue
            
            # Key-Value 파싱
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'Count':
                    # 새 벡터 시작
                    if current_vector and len(current_vector) > 1:
                        vectors.append(current_vector)
                    current_vector = {'count': int(value)}
                elif key == 'Key':
                    current_vector['key'] = value
                elif key == 'IV':
                    current_vector['iv'] = value
                elif key == 'PT' or key == 'PlainText':
                    current_vector['plaintext'] = value
                elif key == 'CT' or key == 'CipherText':
                    current_vector['ciphertext'] = value
                elif key == 'AAD':
                    current_vector['aad'] = value
                elif key == 'Tag':
                    current_vector['tag'] = value
        
        # 마지막 벡터 추가
        if current_vector and len(current_vector) > 1:
            vectors.append(current_vector)
    
    return vectors

def write_tvec(vectors, output_file, algorithm='AES', mode='GCM'):
    """바이너리 포맷으로 작성"""
    alg_id = ALGORITHMS[algorithm]
    mode_id = MODES[mode]
    
    with open(output_file, 'wb') as f:
        # Header (12 bytes)
        magic = 0x43455654  # "TVEC"
        version = 1
        count = len(vectors)
        f.write(struct.pack('<III', magic, version, count))
        
        # Entries
        for v in vectors:
            # Hex string을 bytes로 변환
            key = bytes.fromhex(v.get('key', ''))
            iv = bytes.fromhex(v.get('iv', ''))
            plaintext = bytes.fromhex(v.get('plaintext', ''))
            ciphertext = bytes.fromhex(v.get('ciphertext', ''))
            aad = bytes.fromhex(v.get('aad', ''))
            tag = bytes.fromhex(v.get('tag', ''))
            
            # Entry Header (16 bytes)
            f.write(struct.pack('<BBBBHHHHHH',
                alg_id,
                mode_id,
                len(key),
                len(iv),
                len(plaintext),
                len(ciphertext),
                len(aad),
                len(tag),
                0,  # reserved1
                0   # reserved2
            ))
            
            # Variable data
            f.write(key)
            f.write(iv)
            f.write(plaintext)
            f.write(ciphertext)
            f.write(aad)
            f.write(tag)

def main():
    if len(sys.argv) != 3:
        print("Usage: python nist_to_tvec.py input.txt output.bin")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # 파일명에서 모드 자동 감지
    mode = detect_mode_from_filename(input_file)
    
    print(f"Parsing {input_file}...")
    vectors = parse_nist_gcm(input_file)
    print(f"Found {len(vectors)} test vectors")
    
    print(f"Writing to {output_file}... (Mode: {mode})")
    write_tvec(vectors, output_file, mode=mode)
    print("Done!")

if __name__ == '__main__':
    main()
