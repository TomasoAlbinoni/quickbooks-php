<?php

/** 
 * AES Encryption (depends on mcrypt for now)
 * 
 * Copyright (c) 2010 Keith Palmer / ConsoliBYTE, LLC.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 * 
 * @author Keith Palmer <keith@ConsoliBYTE.com>
 * 
 * @package QuickBooks
 */

// 
QuickBooks_Loader::load('/QuickBooks/Encryption.php');

/**
 * 
 */
class QuickBooks_Encryption_Aes extends QuickBooks_Encryption
{
	static function encrypt($key, $plain, $salt = null)
	{
		if (is_null($salt)) {
			$salt = QuickBooks_Encryption::salt();
		}

		$plain = serialize([$plain, $salt]);

		// Define cipher and key
		$cipher = 'AES-256-OFB'; // OFB mode is supported by OpenSSL
		$ivlen = openssl_cipher_iv_length($cipher);

		// Generate a random IV
		$iv = openssl_random_pseudo_bytes($ivlen);

		// Hash and truncate the key to match required length
		$key = substr(md5($key), 0, 32); // 32 bytes for AES-256

		// Encrypt with raw binary output
		$encrypted_raw = openssl_encrypt($plain, $cipher, $key, OPENSSL_RAW_DATA, $iv);

		// Combine IV and encrypted data, then base64 encode
		$encrypted = base64_encode($iv . $encrypted_raw);

		return $encrypted;
	}
	
	static function decrypt($key, $encrypted)
	{
		// Define cipher and IV length
		$cipher = 'AES-256-OFB';
		$ivlen = openssl_cipher_iv_length($cipher);

		// Hash and truncate the key to match required length
		$key = substr(md5($key), 0, 32); // Or use hash('sha256', $key, true) for better security

		// Decode the base64-encoded string
		$encrypted = base64_decode($encrypted);

		// Extract IV and encrypted data
		$iv = substr($encrypted, 0, $ivlen);
		$ciphertext = substr($encrypted, $ivlen);

		// Decrypt
		$decrypted_raw = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);

		// Unserialize and return the original data
		$decrypted = null;	
		$tmp = unserialize($decrypted_raw);
		if ($tmp) {
			$decrypted = current($tmp);
		}
		return $decrypted;
	}
}
