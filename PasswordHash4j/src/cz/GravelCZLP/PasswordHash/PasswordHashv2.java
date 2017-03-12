package cz.GravelCZLP.PasswordHash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordHashv2 {
	
	/**
	 * Prefix for our hash, every user should change this
	 */
	public static final String ID = "$G$";
	
	/**
	 * basically number of iterations
	 */
	public static final int DEFAULT_COST = 512;
	
	/*
	 * list of usable peppers, you can add your own if you want to
	 */
	private static final char[] pepper = "abcdefghijklopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789".toCharArray();
	
	/**
	 * Algorithm to use, this is the best i know, PM me if you know better one
	 */
	private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
	
	/**
	 * layout of our hash
	 * change the first G to your ID without removing the $
	 * if you changed SIZE you have to generate hash and get the length of it
	 * example token: $G$128$sIfLCAPmizFnaV1qRqkiZAZdfy3ndff_S32EFtht162OiHu_Eu0_UgKw8JuP0yrAtL8WuFfHxi7c9AypiJRGU44bAJQKQEIXpIKYSN1VF7Fh6R-aV_HEh3Wxu5FrBWSa5hwZSaWBZmn203ggQTB5gJ2iXVlK6pUgiVD0du9j-4I
	 * if we split the token by  $
	 *  we get:
	 *  $G = our ID
	 *  $512 = our cost
	 *  $dDGf1rKDRI103VhNZCujG1gL7PNS1sI8hh6z69LTh6hG4KONbmAdDaVFUyuvqGAoiBzdDEZXOfDVfDt202HPDQM6sMU7han2k4Ic0yh0PuXTksq8LFxNKNJap37ICjO1Ljt4NlGdEoXd1k6L8TI0Grx2miCn4P0_G9L6iobi4lbd2z40ZA6eXbo-mTy44OS_WZbe5R1mZTzTEGlGqMcS6as3LxrCBK5F2wsQ_9wrXLIludjKLr2I7Y9GnwMVGTOpS8fZ0wA5kTSWs_jgfZVx1Tn7asqp3p7pJCr9e3ZhJtQaEN-nr0NnaFlkCo65g8dswvKvIy9fRRWpyGSkuz0xxg
	 *  = our hash
	 *  The password is P4ssw0rd1
	 */
	private static final Pattern layout = Pattern.compile("\\$G\\$(\\d\\d\\d?)\\$(.{512})");
	
	/**
	 * Size of PBEKeySpec in method pbkdf2(args...)
	 */
	private static final int SIZE = 1024;

	/**
	 * Our Random
	 */
	private final SecureRandom random;

	private final int cost;
	
	
	public PasswordHashv2() {
		this.cost = DEFAULT_COST;
		iterations(cost);
		byte[] seed = new byte[512]; // random seed
		new SecureRandom().nextBytes(seed); // generate random seed
		this.random = new SecureRandom(seed); // use random seed 
	}
	
	
	// the ~0x80 should be changed by the cost
	// use http://numbermonk.com/hexadecimal/128/en to figure out what it should be
	private static int iterations(int cost) {
	  if ((cost & ~0x200) != 0) {
	    throw new IllegalArgumentException("cost: " + cost);
	  }
	  return 1 << cost;
	}
	
	/**
	 * Hashes password with salt and pepper
	 * @param password The password to hash
	 * @return token of salt,pepper(pepper is not stored),id cost and hash
	 */
	public String hash(String password) {
		byte[] salt = new byte[SIZE / 4]; // size of salt
		random.nextBytes(salt); // generate new salt
		char ppr = pepper[random.nextInt(pepper.length)]; // get random pepper
		password = password + ppr; // add pepper to password
		byte[] dk = pbkdf2(password.toCharArray(), salt, 1 << cost); // hash it
		byte[] hash = new byte[salt.length + dk.length]; // hash it
	    System.arraycopy(salt, 0, hash, 0, salt.length); // idk :D
	    System.arraycopy(dk, 0, hash, salt.length, dk.length); // idk :D
	    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding(); // setup encoder
	    return ID + cost + "$" + enc.encodeToString(hash); // encode hash and return with all other data
	}
	 /**
	  * Detects if user entered in the correct password
	  * @param password the password user entered in
	  * @param token the token of password stored in database
	  * @return true if passwords match
	  */
	public boolean auth(String password, String token) {
		Matcher m = layout.matcher(token); // setup matcher
		if (!m.matches()) { // detect if layout matches
			throw new IllegalArgumentException("Invalid token");
		}
		int iterations = iterations(Integer.parseInt(m.group(1))); // get iterations from token
		byte[] hash = Base64.getUrlDecoder().decode(m.group(2));  // get hash from token 
		byte[] salt = Arrays.copyOfRange(hash, 0, SIZE / 4); // get salt from token
		for (int i = 0; i < pepper.length; i++) { // loop pepper
			char ppr = pepper[i]; // get next pepper
			String passw; // init temporary password
			passw = password + ppr; // add pepper to password
			byte[] check = pbkdf2(passw.toCharArray(), salt, iterations); // hash it
			
			// detect if it matches
			int zero = 0;
		    for (int idx = 0; idx < check.length; ++idx) {
			      zero |= hash[salt.length + idx] ^ check[idx];
		    }
		    if (zero == 0) {
		    	return true;
		    }
		}
		return false;
	}
	/**
	 * Hashes Password
	 * @param password password to hash
	 * @param salt generated random salt
	 * @param iterations how many iterations to use
	 * @return hashed version of password
	 */
	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
		KeySpec spec = new PBEKeySpec(password, salt, iterations, SIZE);
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
			return factory.generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			System.out.println("Invalid SecretKeyFactory: " + e.getMessage());
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			System.out.println("No such algorithm: " + ALGORITHM + " : " + e1.getMessage());
		}
		return new byte[1];
	}
}
