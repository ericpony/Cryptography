/**
SpaceMac : This library provide 3 static methods: mac, combine, and verify
The field of operation is GF(2^8) Rijndael field.

- mac : calculate a SpaceMac tag for an input vector
- combine : combine tags of the combining vectors to generate a valid SpaceMac 
tag for the combination
- verify : verify if a tag is valid for an input vector
The PRG and PRF calls are implemented using AES provided by "javax.crypto". See 
details about input/output of each function below.
*/

import javax.crypto.Cipher; // AES 

import javax.crypto.spec.SecretKeySpec; // key related
import java.security.Key; // key related

import javax.crypto.spec.IvParameterSpec; // iv related
import java.security.spec.AlgorithmParameterSpec; // iv related

public class SpaceMac {
  
	public static final String ALGORITHM = "AES";
	public static final String CIPHER = "AES/CBC/PKCS5Padding"; 		
	public static final short MAX_ID = 100;	
	private static short[][] products;
	
	// Precalculate all the products
	static {
		products = new short[256][256]; // storing products of all pairs in GF(2^8)
		for (int i=0; i<256; i++)
			for (int j=0; j<256; j++)
				products[i][j] = gmul(i,j);
	}
	
	// Compute a SpaceMac tag for a vector given a key pair (k1,k2), 
	// space id, the vector, parameters n and m
	//
	// INPUT
	// k1 : key for the PRG - a byte array of size 16
	// k2 : key for the PRF - a byte array of size 16
	// id : id of the space - an short in range 1 to MAX_ID
	// n : number of symbols, e.g., 1019
	// m : number of vectors per generation, e.g., 5	
	// y : input vector to generate tag - a short array of size (n+m)		
	// iv : the IV used with AES - a byte array of size 16
	//
	// OUTPUT
	// t : tag of y under key (k1,k2) - type short but value is in GF(2^8)
	public static short mac(byte[] k1, byte[] k2, short id, 
				short n, short m, short[] y, byte[] iv) throws Exception {
		short i; // generic counter
		short[] r; // r from PRG on k1
		short[] f; // contains m PRF values resulted from F(k2, id, j) j=1..m
		byte[] msg; // msg to encrypt
		byte[] encVal; // encrypted value
		Key key1, key2; // keys used for the encryption, corresponding to k1, k2
		int t; // output tag
		AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
	
		// sanity check
		if (k1.length!=16 || k2.length!=16 || id<1 || id>MAX_ID || y.length!=(n+m))
			return -1; // error
		
		// ------------------------------------------- 1. get r from a PRG on k1
		// PRG is implemented using AES
		
		// msg must be at least (n+m) bytes		
		msg = new byte[n+m];
		for (i=0; i<n+m; i++) 
			msg[i] = (byte) i;				
		key1 = new SecretKeySpec(k1, ALGORITHM);				
		Cipher c = Cipher.getInstance(CIPHER);
		c.init(Cipher.ENCRYPT_MODE, key1, paramSpec);
		encVal = c.doFinal(msg);	
		r = getR( (short) (n+m),encVal);
		// encVal will have length at least (n+m)
		// the first (n+m) bytes is used as r		
								
		//  ------------------------------------------- 2. get the f's = F(k2, id, j)'s 
		// PRF is also implemented using AES
		key2 = new SecretKeySpec(k2, ALGORITHM);												
		c.init(Cipher.ENCRYPT_MODE, key2, paramSpec);
		f = new short[m];
		for (i=0; i<m; i++) {					
			msg = new byte[4]; // msg is composed of id and i
			msg[0] = (byte) id;
			msg[1] = (byte) (id>>>8);
			msg[2] = (byte) i;
			msg[3] = (byte) (i>>>8);				
			encVal = c.doFinal(msg);
			f[i] = (short) (encVal[0] & 255); // use the first byte, treat the byte as unsigned
		}
		
		// --------------------------------------------- 3. Computing the tag using r,f,y		
		t = 0;
		for (i=0; i<n+m; i++)	
			t ^= products[ r[i] ][ y[i] ]; // adding in GF(2^8) is XOR					
		for (i=0; i<m; i++)
			t ^= products[ y[n+i] ][ f[i] ];		
				
		return (short) t;
	}
	
	// Verify if an input tag t is a valid tag for vector y under key k=(k1,k2)
	//
	// INPUT
	// k1 : key for the PRG - a byte array of size 16
	// k2 : key for the PRF - a byte array of size 16
	// id : id of the space - an short in range 1 to MAX_ID
	// n : number of symbols, e.g., 1019
	// m : number of vectors per generation, e.g., 5
	// y : input vector to generate tag - a short array of size (n+m)
	// iv : the IV used with AES - a byte array of size 16
	// t : tag of the vector to check
	//
	// OUTPUT
	// true if the tag is valid, false otherwise
	public static boolean verify(byte[] k1, byte[] k2, short id, 
			short n, short m, short[] y, byte[] iv, short t) throws Exception {
		return ( t==mac(k1,k2,id,n,m,y,iv) );
	}
	
	
	// Combine tags to generate a valid new tag
	//
	// INPUT
	// tags : tags of the incoming vectors that are combined into an outgoing vector
	// alphas : local coding coefficents for the incoming vectors
	//
	// OUTPUT
	// t : tag of the combined vector
	public static short combine(short[] tags, short[] alphas) {
		int i, t;
		
		// sanity check
		if (tags.length != alphas.length) return -1;
		
		// t is just a linear combination
		t = 0;
		for (i=0; i<tags.length; i++)
			t ^= products[ alphas[i] ][ tags[i] ];
		
		return (short) t;
	}
	
				
	
	//--------------------- BELOW ARE PRIVATE HELPER METHODS ---------------------
	
	// Get r of the PRG from an AES encryption
	private static short[] getR(short size, byte[] encVal) {
		short[] r = new short[size];
		for (short i=0; i<size; i++)
			r[i] = (short) (encVal[i] & 255); // treat the byte as unsigned byte
		return r;
	}
	
	// Multiply two numbers in GF(2^8) finite field defined by the 
	// polynomial x^8 + x^4 + x^3 + x + 1 using 
	// the "peasant's algorithm"
	private static short gmul(int a, int b) {
		int p=0;
		int counter;
		boolean hiBitSet;
		
		for (counter=0; counter<8; counter++) {
			if ( (b&1) == 1) // low bit of b is set
				p ^= a;
			hiBitSet = ( (a & 128)> 0); // if hi bit of a is set
			a <<= 1;
			a &= 255;
			if (hiBitSet) 				
				a ^= 27; // xor with x^4 + x^3 + x + 1
			b >>>= 1;
		}
		
		return (short) p;
	}			
}
