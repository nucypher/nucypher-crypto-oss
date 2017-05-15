package com.nucypher.crypto;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.encoders.Hex;

public class SubzoneKeyDerivation {
	
	public static final Digest DIGEST = new SHA256Digest();
	public static final int SEED_LENGTH_BYTES = (128+128)/8; // seed = IV + Key (AES-128)
	
	
	public static byte[] deriveSeed(String ezkeyName, String ezkeyVersion, byte[] ezkeyMaterial, int subzoneID, int numberSubzones, byte[] salt){

	        byte[] info = null;
			try {
				info = (subzoneID+"/"+numberSubzones+"/"+ezkeyName+"/"+ezkeyVersion).getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        byte[] seed = new byte[SEED_LENGTH_BYTES];

	        HKDFParameters params = new HKDFParameters(ezkeyMaterial, salt, info);
	        

	        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(DIGEST);
	        hkdf.init(params);
	        hkdf.generateBytes(seed, 0, SEED_LENGTH_BYTES);
	        
	        return seed;

	}
	
	public static byte[] deriveSeed(String ezkeyName, String ezkeyVersion, byte[] ezkeyMaterial, int subzoneID, int numberSubzones){
		return deriveSeed(ezkeyName, ezkeyVersion, ezkeyMaterial, subzoneID, numberSubzones, null);
	}

	
	public static void main(String args[]){

       String ezKeyName = "ezKeyName1";
       String ezKeyVersion = "ezKeyVersion1.1";
       byte[] ezKeyMaterial = Hex.decode("00010203040506070809101112131415");
       
       int nSubzones = 10;
       
       for(int subzoneID=0; subzoneID<nSubzones; subzoneID++){
    	   byte[] seed = SubzoneKeyDerivation.deriveSeed(ezKeyName, ezKeyVersion, ezKeyMaterial, subzoneID, nSubzones);
    	   System.out.println(Hex.toHexString(seed));
       }
        
        

	}
	
//	private static void writeJson(Map map, OutputStream os) throws Exception {
//	    Writer writer = new OutputStreamWriter(os, Charsets.UTF_8);
//	    ObjectMapper jsonMapper = new ObjectMapper();
//	    jsonMapper.writerWithDefaultPrettyPrinter().writeValue(writer, map);
//	  }

}
