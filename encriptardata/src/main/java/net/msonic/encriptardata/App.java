package net.msonic.encriptardata;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;

import com.google.common.collect.Lists;
import com.google.gson.JsonObject;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;


/**
 * Hello world!
 *
 */
public class App 
{
	
	public  static String encriptar() throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

		
		
		File f = new File("/Users/manuelzegarra/Desktop/cert/cert2/public_key.der");
		
        X509Certificate cert = X509Certificate.getInstance(new FileInputStream(f));




        Cipher encryptCipher = Cipher.getInstance("RSA");

        encryptCipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());

        
        String message = "111111";
        byte[] messageACrypter = message.getBytes();
        byte[] messageCrypte = encryptCipher.doFinal(messageACrypter);

        //Log.d(MainActivity.class.getCanonicalName(),"message : "+message);
        String messageCrypteB64 = new String(Base64.encode(messageCrypte));
        //Log.d(MainActivity.class.getCanonicalName(), "messageCrypteB64 : '" + messageCrypteB64 + "'");
        System.out.println("Source crypted: "+ messageCrypteB64);
        
        return messageCrypteB64;
	}
	
    public static void main( String[] args )
    {
    	
    	
    	
    /*	String message1 = "secret message";
        byte[] messageACrypter = message1.getBytes();
        String messageCrypteB64 = new String(Base64.encode(messageACrypter));
        System.out.println(messageCrypteB64);
        System.out.println("=========");*/
        
    	
    	
    		
    	try {
    		
    		/*
    		String trama = "oxLFCXW+K3OiyfQp6sR7gLxk8d279sUh1QH5zg44DG1EnJ7ob6emVrDa6OsTfJlXCBum2D5tLEbd" +
    "R5p1fFO5n8tAdPdF8lfzA1iS+lHl8rYnzVnqAdf8kJ2+agJG94xx5xiogrUYO5H+tcngEJc+Jlm7" +
    "wmnDIcalO9q2fbmlM5r2XFYf2C8JLdSk/6NvuujwB8Q4GK9tkhMy4RlbdvcpyF9YC0vQaLNCebaH" +
    "84JpeuQcKJRzCG8ADYBhPEJe8V5eXeAOeiUXlK18zqwfIB2CsHMBM+5CigH3XEq0c8yknn6QxYho" +
    "EB99svoLM8tTxnic9MpxY8fge+MLgVnz6k7U0Q4FR06sMXOexycTdCDBKNmw2pyvS+ZDH7zgR1UM" +
    "VpM2F1onHWTJaWcnxe0xEp0gGQFybgXx9z+e1LPQ74hHBtAgPpu67f/NHTdEQeoulcau/3F3sKNC" +
    "6xZw0N6HyLBR9v8yelNCkIqW8XuvBiVaTTvvAJ0Jn//bv8kwh3nbJd3gOszaWzxhnOE0rjvVZE1u" +
    "FdCf99yzSAqGqX+vFo09n/FqpXRSbwXC5W58msioLvNu4hD37pjVSXJsT8ovRm/I5ooSLRVFalSR" +
    "kUWYW8jgUlNNv+9bowQVLM4aEh+M4tsABSWXQ8ASTpXkLLJeSbDw4o3af/TTBci+BfQL87k2wJ4=";*/
    		
    		
    		
    		
    		String trama = "pCjULbzCZLTmPxa9Wc/TxidqTZgVhLw0DKz8N95l/IayzQBcGTxsNgStDedNK35zwONPbDYXyIBUgn6FwesXz9IiHkFWMqssmlLXfQ0lZEnkYKu3p+SqQInj2ssgONy6HPVLpnsIqmrKBalgoT6poIk9m8tsF12MeDfyOI4Woe8Uzs7soO5essYnBnM+wYvRmPXQRU8x02/Kmbohl1ef7A0Jrv42WDwK3CThojmBI8pgzCRn9eQdGKwyaCwzYp4qE3gqN164MEys9noujCJfZM28OCvI0IelSaWO5TR3yBciTW8/EefGjp4q57RZ7JQktJptlr+uTbNcnPdgz96NZw==";
    		
    		//trama =  encriptar();
    		
    		Security.addProvider(new BouncyCastleProvider());

			PrivateKey privateKey = getPrivateKey("/Users/manuelzegarra/Desktop/cert/cert3/private.pem");
			
			
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
	        rsa.init(Cipher.DECRYPT_MODE, privateKey);
	        
	        
	        byte[] data = Base64.decode(trama.getBytes());
	        
	        byte[] messageCrypte = rsa.doFinal(data);
	        
	        String message = new String(messageCrypte);
	        System.out.println(message);
	       // byte[] utf8 = rsa.doFinal(buffer);
	        //return new String(utf8, "UTF8");
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
    	
        //System.out.println( "Hello World!" );
    }
    
    
    public static PrivateKey getPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    	
    		
    	
    	File f = new File(filename);
    	KeyPair readKeyPair = readKeyPair(f, "abc123");
    	return readKeyPair.getPrivate();
    	
    	
    }
    
    
    private static KeyPair readKeyPair(File privateKey, String keyPassword) throws IOException {
        FileReader fileReader = new FileReader(privateKey);
        PEMReader r = new PEMReader(fileReader, new DefaultPasswordFinder(keyPassword.toCharArray()));
        try {
            return (KeyPair) r.readObject();
        } catch (IOException ex) {
            throw ex;
        } finally {
            r.close();
            fileReader.close();
        }
    }
    
    
    private static class DefaultPasswordFinder implements PasswordFinder {

        private final char [] password;

        private DefaultPasswordFinder(char [] password) {
            this.password = password;
        }

        @Override
        public char[] getPassword() {
            return Arrays.copyOf(password, password.length);
        }
    } 
    
    
    
    private static final String AUDIENCE = "NotReallyImportant";
    private static final String ISSUER = "YourCompanyOrAppNameHere";
    private static final String SIGNING_KEY = "LongAndHardToGuessValueWithSpecialCharacters@^($%*$%";

    
    public static String jwtGenerate(String userId, Long durationDays){
    	
    	//Current time and signing algorithm
        Calendar cal = Calendar.getInstance();
        HmacSHA256Signer signer;
        
        try {
            signer = new HmacSHA256Signer(ISSUER, null, SIGNING_KEY.getBytes());
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        
        
      //	Configure JSON token
        JsonToken token = new net.oauth.jsontoken.JsonToken(signer);
        token.setAudience(AUDIENCE);
        token.setIssuedAt(new org.joda.time.Instant(cal.getTimeInMillis()));
        token.setExpiration(new org.joda.time.Instant(cal.getTimeInMillis() + 1000L * 60L * 60L * 24L * durationDays));
        
        //Configure request object, which provides information of the item
        JsonObject request = new JsonObject();
        request.addProperty("userId", userId);
        
        JsonObject payload = token.getPayloadAsJsonObject();
        payload.add("info", request);
        
        
        
        try {
            return token.serializeAndSign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        

        
        
        
    }
    
    
    
    
    public static TokenInfo verifyToken(String token)  
    {
        try {
            final Verifier hmacVerifier = new HmacSHA256Verifier(SIGNING_KEY.getBytes());

            VerifierProvider hmacLocator = new VerifierProvider() {

                @Override
                public List<Verifier> findVerifier(String id, String key){
                    return Lists.newArrayList(hmacVerifier);
                }
            };
            VerifierProviders locators = new VerifierProviders();
            locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
            net.oauth.jsontoken.Checker checker = new net.oauth.jsontoken.Checker(){

                @Override
                public void check(JsonObject payload) throws SignatureException {
                    // don't throw - allow anything
                }

            };
            //Ignore Audience does not mean that the Signature is ignored
            JsonTokenParser parser = new JsonTokenParser(locators,
                    checker);
            JsonToken jt;
            try {
                jt = parser.verifyAndDeserialize(token);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
            JsonObject payload = jt.getPayloadAsJsonObject();
            TokenInfo t = new TokenInfo();
            String issuer = payload.getAsJsonPrimitive("iss").getAsString();
            String userIdString =  payload.getAsJsonObject("info").getAsJsonPrimitive("userId").getAsString();
            if (issuer.equals(ISSUER) && !(userIdString.compareTo("")==0))
            {
                t.setUserId(userIdString);
                t.setIssued(new DateTime(payload.getAsJsonPrimitive("iat").getAsLong()));
                t.setExpires(new DateTime(payload.getAsJsonPrimitive("exp").getAsLong()));
                return t;
            }
            else
            {
                return null;
            }
        } catch (InvalidKeyException e1) {
            throw new RuntimeException(e1);
        }
    }


}

    
    
  
