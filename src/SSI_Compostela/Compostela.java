package SSI_Compostela;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Compostela {

	public static void main(String[] args) {
		
		Peregrino pilgrim = new Peregrino("adrian", "fernandez", "44478888Q", "22/10/2014", "Camelias", "religion", "Peregrino.publica", "Peregrino.privada");
		Albergue hostel1 = new Albergue("1", "23/10/1014", "valenzana", "n/a", "Albergue1.publica", "Albergue1.privada");
		Albergue hostel2 = new Albergue("2", "24/10/1014", "lagunas", "n/a", "Albergue2.publica", "Albergue2.privada");
		Oficina oficina = new Oficina("Oficina.publica", "Oficina.privada");
		Vector<String> idAlbergue = new Vector<String>();
		idAlbergue.add("1");
		idAlbergue.add("2");
		Map<String,PublicKey> publicKeys = new LinkedHashMap<String,PublicKey>(); 
		publicKeys.put("1", hostel1.getPublicKey());
		publicKeys.put("2", hostel2.getPublicKey());
		Paquete paquete = pilgrim.generarCompostela(pilgrim.getPublicKey());
		paquete = hostel1.sellarCompostela(paquete, oficina.getPublicKey());
		paquete = hostel2.sellarCompostela(paquete, oficina.getPublicKey());
		oficina.desempaquetarCompostela(paquete, idAlbergue, pilgrim.getPublicKey(), publicKeys);

	}

}

class Participante{
	
	protected PublicKey publicKey;
	protected PrivateKey privateKey;
	protected KeyPair keypair;
	protected File publicKeyFile;
	protected File privateKeyFile;

	public Participante(String pathClavePublica, String pathClavePrivada) {
		this.privateKeyFile = new File(pathClavePrivada);
		this.publicKeyFile = new File(pathClavePublica);
		loadKeys();
		keypair = new KeyPair(this.publicKey,this.privateKey);
	}

	protected void loadKeys() {
		Security.addProvider(new BouncyCastleProvider()); 
		try {
			KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
			/*** 2 Recuperar clave Privada del fichero */
			// 2.1 Leer datos binarios PKCS8
			byte[] bufferPriv = new byte[5000];
			FileInputStream in = new FileInputStream(this.privateKeyFile);
			in.read(bufferPriv, 0, 5000);
			in.close();

			// 2.2 Recuperar clave privada desde datos codificados en formato
			// PKCS8
			PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
			this.privateKey = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

			/*** 4 Recuperar clave PUBLICA del fichero */
			// 4.1 Leer datos binarios x809
			byte[] bufferPub = new byte[5000];
			in = new FileInputStream(this.publicKeyFile);
			in.read(bufferPub, 0, 5000);
			in.close();

			// 4.2 Recuperar clave publica desde datos codificados en formato
			// X509
			X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
			this.publicKey = keyFactoryRSA.generatePublic(clavePublicaSpec);

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (FileNotFoundException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (IOException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			System.out.println("Error en la carga de claves " + e.getMessage());
		}

	}
	
	protected SecretKey createSecretKey() {
		KeyGenerator generadorDES;
		SecretKey secretKey = null;

		try {
			generadorDES = KeyGenerator.getInstance("DES");
			generadorDES.init(56);
			secretKey = generadorDES.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en la creacion de la clave secreta");
		}
		return secretKey;
	}
	
	protected byte[] cipherData(byte[] bytes, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance("DES", "BC");
			cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
			bufferCifrado = cifrador.doFinal(bytes);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		}
		return bufferCifrado;
	}
	
	protected byte[] cipherSecretKey(PublicKey clavePublica, SecretKey secretKey) {
		byte[] bufferCifrado = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, clavePublica); 
			bufferCifrado = cipher.doFinal(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (BadPaddingException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en el cifrado " + e.getMessage());
		}
		return bufferCifrado;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}
}

class Peregrino extends Participante{
	
	private Map<String,String> data;
	private Utils json;
	private String dataJson;
	private byte[] dataJsonBytes;
	private SecretKey secretKey;
	private byte[] dataEncrypted;
		
	Peregrino(String name, String surname, String DNI, String date,
			String address, String motivations, String publicKeyFile,
			String privateKeyFile){
		
		super(publicKeyFile, privateKeyFile);
		data = new LinkedHashMap<String,String>();
		json = new Utils();
		data.put("name", name);
		data.put("surname", surname);
		data.put("DNI", DNI);
		data.put("date", date);
		data.put("motivations", motivations);
		dataJson = json.map2json(data);
		dataJsonBytes = dataJson.getBytes();
		this.secretKey = createSecretKey();
		dataEncrypted = this.cipherData(dataJsonBytes, secretKey);
		
		
	}
	
	public Paquete generarCompostela(PublicKey publicaOficina) {
		// Cifrar datos
		
		Paquete paquete = new Paquete();
		paquete.anadirBloque("PILGRIM"+"data", new Bloque("dataCipherPilgrim", dataEncrypted));
		
		// Cifrar Clave Secreta
		paquete.anadirBloque("PILGRIM"+"secretKey",new Bloque("secretKeyPilgrim",this.cipherSecretKey(publicaOficina, secretKey)));

		// Firmar
		paquete.anadirBloque("PILGRIM"+"signature", signatureData());
		
		
		return paquete;
	}
	
	private Bloque signatureData() {
		byte[] sign = null;
		try {
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initSign(privateKey);
			signature.update(this.dataEncrypted);
			
			sign = signature.sign(); // FRAN
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println("Error en la firma" + e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error en la firma" + e.getMessage());
		}
		return new Bloque("signature", sign);
	}
}


class Albergue extends Participante{
	
	private String idAlbergue;
	private Map<String,String> data;
	private Utils json;
	private String dataAlbergueJson;
	private byte[] dataAlbergueJsonBytes;
	private byte[] dataAlbergueEncrypted;
	private SecretKey secretKey;
	
	Albergue(String idAlbergue, String date, String address,String incidents,String publicKeyFile, String privateKeyFile){
		super(publicKeyFile, privateKeyFile);
		this.idAlbergue = idAlbergue;
		data = new LinkedHashMap<String,String>();
		json = new Utils();
		data.put("date", date);
		data.put("address", address);
		data.put("incidents", incidents);
		dataAlbergueJson = json.map2json(data);
		dataAlbergueJsonBytes = dataAlbergueJson.getBytes();
		this.secretKey = createSecretKey();
		dataAlbergueEncrypted = this.cipherData(dataAlbergueJsonBytes, secretKey);
	}
	
	public Paquete sellarCompostela(Paquete paquete, PublicKey publicaOficina) {
		this.addDataHosteltoPackage(paquete);
		byte[] sign=null;
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(paquete.getBloque("PILGRIM"+"signature").getContenido());
			messageDigest.update(dataAlbergueEncrypted);
			byte[] hash = messageDigest.digest();

			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initSign(this.privateKey);
			signature.update(hash);
			sign = signature.sign();

		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en resumen paquete" + e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "SECRET_KEY", new Bloque("idAlbgSecretKey",
				this.cipherSecretKey(publicaOficina, this.secretKey)));
		paquete.anadirBloque("ALBERGUE" + idAlbergue + "SIGN", new Bloque(
				"signAlbergue", sign));
		return paquete;
	}

	private void addDataHosteltoPackage(Paquete paquete) {
		
		paquete.anadirBloque("ALBERGUE"+this.idAlbergue+"DATA",new Bloque(this.idAlbergue+"DATA", this.dataAlbergueEncrypted));
	}

	
}

class Oficina extends Participante{
	
	Utils json;
	
	Oficina(String publicKeyFile,String privateKeyFile){
		super(publicKeyFile, privateKeyFile);
		
		json = new Utils();
	}
	
	public void desempaquetarCompostela(Paquete paquete,
			Vector<String> idAlbergue, PublicKey publicKeyPeregrino,
			Map<String, PublicKey> publicKeysAlbergue){
		
		
		
		//verificar firma ALbergue
		SecretKey secretKeyAlbergue;
		Signature signatureAlbergue;
		String data;
		byte[] skAlbergue;
		byte[] signAlbergue;
		byte[] dataAlbergue;
		byte[] signaturePilgrim;
		 
		for (int i = 0; i < idAlbergue.size();i++){
			String id = idAlbergue.get(i);
			
			dataAlbergue = paquete.getBloque("ALBERGUE"+id+"DATA").getContenido();
			signAlbergue = paquete.getBloque("ALBERGUE" + id + "SIGN").getContenido();
			skAlbergue = paquete.getBloque("ALBERGUE" + id + "SECRET_KEY").getContenido();
			signaturePilgrim = paquete.getBloque("PILGRIM"+"signature").getContenido();
			
			try{
				MessageDigest messageDigest = MessageDigest.getInstance("MD5");
				messageDigest.update(paquete.getBloque("PILGRIM"+"signature").getContenido());
				messageDigest.update(dataAlbergue);
				byte[] hash = messageDigest.digest();
				
				Signature signature = Signature.getInstance("MD5withRSA", "BC");
				signature.initVerify(publicKeysAlbergue.get(id));
				signature.update(hash);
				boolean verifySign = signature.verify(signAlbergue);
				
				if(verifySign){
					System.out.println("Firma verificada Albergue:" + id);
					secretKeyAlbergue = this.decryptSecretKey(skAlbergue);
					data = new String(this.decrytpData(dataAlbergue, secretKeyAlbergue));
					Map<String, String> datos2 = json.json2map(data);
			        System.out.print("MAP: ");
			        for (Map.Entry<String, String> entrada : datos2.entrySet()) {
			            System.out.print(entrada.getKey() + "->" + entrada.getValue() + " ");
			        }
				} else {
					System.out.println("Error, invalid signature of Hostel "+id);
				}
				
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			
		}
		
		//Verificar firma peregrino
		boolean verifySignPilgrim=false;
		SecretKey secretKeyPilgrim;
		
		String dataPilgrim = null;
		byte[] skPilgrim = paquete.getBloque("PILGRIM"+"secretKey").getContenido();
		byte[] signPilgrim = paquete.getBloque("PILGRIM"+"signature").getContenido();
		byte[] dataBytesPilgrim = paquete.getBloque("PILGRIM"+"data").getContenido();
		
		
		try {
			Signature signature = Signature.getInstance("MD5withRSA", "BC");
			signature.initVerify(publicKeyPeregrino);
			signature.update(dataBytesPilgrim);
			verifySignPilgrim = signature.verify(signPilgrim);
		} catch (InvalidKeyException e) {
			System.out.println("Error, invalid key in verify sign of pilgrim");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error in the creation of the object signature" + e.getMessage());
		} catch (NoSuchProviderException e) {
			System.out.println("Error in the creation of the object signature " + e.getMessage());
		} catch (SignatureException e) {
			System.out.println("Error, invalid key in verify sign of pilgrim");
		}
		
		if(verifySignPilgrim){
			System.out.println("Firma Pilgrim verificada");
			secretKeyPilgrim = this.decryptSecretKey(skPilgrim);
			
			
			
			dataPilgrim = new String(this.decrytpData(dataBytesPilgrim, secretKeyPilgrim));
			Map<String, String> datos2 = json.json2map(dataPilgrim);
	        System.out.print("MAP: ");
	        for (Map.Entry<String, String> entrada : datos2.entrySet()) {
	            System.out.print(entrada.getKey() + "->" + entrada.getValue() + " ");
	        }
		} else{
			System.out.println("Error, sign pilgrim not verificated");
		}
		
	}
	
	private SecretKey decryptSecretKey(byte[] cipherSecretKey) {
		byte[] buffer=null;
		SecretKey secretKey = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			buffer = cipher.doFinal(cipherSecretKey);
			SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
			DESKeySpec DESspec = new DESKeySpec(buffer);
			secretKey = secretKeyFactoryDES.generateSecret(DESspec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // Hace uso del provider BC
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return secretKey;
	}
	
	private byte[] decrytpData(byte[] data, SecretKey secretKey){
		Cipher cipher;
		byte[] toret=null;
		
		
		try {
			cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			toret = cipher.update(data);
			toret = cipher.doFinal();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return toret;
	}
	
	
}

