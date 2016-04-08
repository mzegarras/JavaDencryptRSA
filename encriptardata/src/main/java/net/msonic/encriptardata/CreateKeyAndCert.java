package net.msonic.encriptardata;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Base64;

public class CreateKeyAndCert {
	
	/*
	 igInteger modulus = new BigInteger("F56D...", 16);
BigInteger pubExp = new BigInteger("010001", 16);

KeyFactory keyFactory = KeyFactory.getInstance("RSA");
RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, pubExp);
RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] cipherData = cipher.doFinal(text.getBytes());


===============
String modulusBase64 = "..."; // your Base64 string here
BigInteger modulus = new BigInteger(1,
        new Base64Encoder.decode(modulusBase64.getBytes("UTF-8")));
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
RSAPublicKeySpec ks = new RSAPublicKeySpec(modulus, pubExp);
RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(KeySpec);

	 * */
	public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		KeyPairGenerator kpg;
		try {
			// Create a 1024 bit RSA private key
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(4096);
			KeyPair kp = kpg.genKeyPair();
			Key publicKey = kp.getPublic();
			Key privateKey = kp.getPrivate();

			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = (RSAPublicKeySpec) fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = (RSAPrivateKeySpec) fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			
			saveToFile("d:\\public.key", pub.getModulus(), pub.getPublicExponent());
			saveToFile("d:\\private.key", priv.getModulus(), priv.getPrivateExponent());
			
			
			
			
			
			BigInteger modulus = new BigInteger( pub.getModulus().toString());
			BigInteger pubExp = new BigInteger( pub.getPublicExponent().toString());

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, pubExp);
			RSAPublicKey key_public = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
			
			
			
			
			
			

			//RSAPublicKey key_public = (RSAPublicKey) fact.generatePublic(pub);
			
			Cipher encryptCipher = Cipher.getInstance("RSA");
		    encryptCipher.init(Cipher.ENCRYPT_MODE, key_public);

		    
		    String message = "TEST ENCRIPT 123";
	        byte[] messageACrypter = message.getBytes();
	        byte[] messageCrypte = encryptCipher.doFinal(messageACrypter);

	        //Log.d(MainActivity.class.getCanonicalName(),"message : "+message);
	        String messageCrypteB64 = new String(Base64.encode(messageCrypte));
	        //Log.d(MainActivity.class.getCanonicalName(), "messageCrypteB64 : '" + messageCrypteB64 + "'");
	        System.out.println("Source crypted: "+ messageCrypteB64);

	        
	        
	        
	        
	    	BigInteger modulus1 = new BigInteger( priv.getModulus().toString());
			BigInteger pubExp1 = new BigInteger( priv.getPrivateExponent().toString());
	    	RSAPrivateKeySpec pubKeySpec1 = new RSAPrivateKeySpec(modulus1, pubExp1);
	    	RSAPrivateKey priv1  = (RSAPrivateKey)keyFactory.generatePrivate(pubKeySpec1);
	        
	        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
	        rsa.init(Cipher.DECRYPT_MODE, priv1);
	        
	        
	        byte[] data = Base64.decode(messageCrypteB64.getBytes());
	        
	        byte[] messageuNCrypte = rsa.doFinal(data);
	        
	        String message1 = new String(messageuNCrypte);
	        System.out.println("Source UNcrypted: "+ message1);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

}