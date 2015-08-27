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
    		
    		
    		String trama = "iqqWErhVHfCBRQ6dJjhc/GBGCS8XuJVPspQ+WVCPOcXVMjQf2x5RG4deXdOf1CHClSrTw/EwhWo6" +
    "zrecW7q+QouiPEEE5efiJEY9oZE4VrlokeP6mPf5jkTloh0SMDEFzEjAN6Kyf4TVcgjieieDI4ri" +
    "jLMbkCU6mkBhlucA0gDviZYYv99QgEWsVFf3vPHWU8MoXdK85fxRtfEER41CcW0pvSVhchXG15cA" +
    "E32hHB4tB7pVceVzWIyvr5cJiTDp+JmYyRagNFdptS/dIoaYqT4FL3zKKRcnj7oMqCbSzjPgtT6C" +
    "ysGBPUhUPS6RJkb5TmRSbids01OLBIse1jIQM/DsrE34DGxCONmLT3p+2EfUaxbigTmVlHGOQdht" +
    "Gvc6StIBZKYbY8u6UmYRzgrJuR+PnACf4AjDkKDrbIz/maUDa9mohPmM4w5aXbL48tYKABV6xwW9" +
    "i+3Lia6mv/ZClbnnChYl/1lhfgf9yYiA0e3BuxpoAwtM6FZi7GzoEBF6WqId5MmKX64U09goSd0k" +
    "5ldvp6SZd4YCOv0P/b26/ShItqq3gD3luLPuqWgUwQlPrw8AQntzOODpUQAIQe/b8UecxP3dQ+3n" +
    "36EYUdkRl5OQYIFrhvgeI0uQyU0FJn4oZFe3eG3083h3/dTbLngG8dzxydE+I3uIPgrFnTpDSd0=";
    		
    		
    		
    		
    		//String trama = "KITtCvXUBbFHFslYt0MTZbR29d7ef38x8mKk0on9Kjr42uIJkQFMozGFcGkR2wlq86PUYpZHmbKEY8n/jQd3KgFphb1fdPO5XiuDJiudB1huHZQjpKYt1l5CkQMhLwxB4oJ9ZBWgax1xPJGx0VlV+ZUhJwIDl0nlFCu52L9JM4+l6Wzx9ilx9UTYlAEyT8z+tZdWxmYuKyTCBveNFvXc4ElhbO0YY4IHvAHtxBWLa7L0ziBExPoh8oEeqaplfpgiuoNhF0Ei2zouN8IMyqt9a8twCtZBCFJhfjDMuYZI+jt2tbRQamqbGm5uzbjH0FMiAzgqCNw1lZVxZmjGXgsrPRhe0MNFL+M295+04uxlg6x/msgfkWW6yWRvmODiY8b2peRnY+J165vmxYlQ5QV43QLlE6JIKF+IHkWv/kFeyCyQFR9/Vk9Nbn8mdAm1VKIdXfM0t4SfSMj/j07AQW+Fg2Dva0Y8A/uHROClOcH3yhLvUoFpjxnO87fXsyl7hUBhQH0nCuMLV0RvqZW/gC/aXG4WT6TjqqJoWq/XjhS392B/jmlCj12ltFzc+FLuGmIvB1qg8XE3rURv1ZWLWXkTjWQJhJJ83fnAkHJAGepjOL9iT7OIfg+mKUNQxLv8/TVBHRC9o7yaha7nKiPWM3WK0szZk6AMdJhQtGHVfRj+LR4=";
    		
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

    
    
  
