@Grab(group='org.bouncycastle', module='bcprov-jdk15on', version='1.68')

import org.bouncycastle.jce.provider.BouncyCastleProvider
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import java.security.Security
import java.util.Base64

// Add Bouncy Castle Provider
Security.addProvider(new BouncyCastleProvider())

def generateRandomIV(int length) {
    String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    SecureRandom random = new SecureRandom()
    StringBuilder iv = new StringBuilder(length)
    for (int i = 0; i < length; i++) {
        iv.append(chars.charAt(random.nextInt(chars.length())))
    }
    return iv.toString()
}

def encryptWithKey(String text, String key) {
    // Ensure the key is 32 bytes for AES 256
    byte[] keyBytes = key.bytes
    if (keyBytes.length != 32) {
        throw new IllegalArgumentException("Key must be 32 bytes for AES 256")
    }

    // Generate a secure random 16-character IV
    String ivString = generateRandomIV(16)
    byte[] ivBytes = ivString.bytes
    IvParameterSpec iv = new IvParameterSpec(ivBytes)

    // Secret key specification
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES")

    // Cipher instance
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC")
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv)

    // Encrypt the text
    byte[] encryptedBytes = cipher.doFinal(text.bytes)

    // Encode encrypted text to Base64
    String encryptedText = Base64.encoder.encodeToString(encryptedBytes)

    return [encryptedText: encryptedText, ivText: ivString]
}

// Example usage
def key = "" // 32-byte key
def text = ""
def result = encryptWithKey(text, key)

println "Encrypted Text: ${result.encryptedText}"
println "Initialization Vector: ${result.ivText}"
println "Concatenation of IV and Encrypted Text: ${result.ivText}${result.encryptedText}"