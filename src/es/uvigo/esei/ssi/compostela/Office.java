package es.uvigo.esei.ssi.compostela;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/*
 * Office es la clase que se utiliza para desempaquetar la compostela.
 * Se verifican las firmas de los albergues y del peregrino y en caso de 
 * que sean correctas se desencriptaran todos los datos de los albergues
 * y de la oficina para su posterior visualizacion en pantalla.
 * 
 *  @author: Adrian Celix Fernandez
 *  @author: Tamara Gonzalez Gomez
 */
public class Office extends Member {
	
	private byte[] dataPilgrim;
	private byte[] secretKeyPilgrim;
	private byte[] signPilgrim;
	private byte[] dataHostel;
	private byte[] secretKeyHostel;
	private byte[] signHostel;

	public Office(String pathPublicKey, String pathPrivateKey) {
		super(pathPublicKey, pathPrivateKey);
	}

	/*
	 * Metodo que desempaqueta el mapa compostela. Se verifican las firmas
	 * y en caso de que sean validas se mostraran por pantalla los correspondientes
	 * datos. En caso de que la firma de uno de los albergues o del peregrino no
	 * sean validas se mostrara un mensaje de error en pantalla y se abortara 
	 * la ejecucion.
	 * @compostela: Mapa compostela que contiene los datos del peregrino y de los
	 * albergues por los que ha pasado dicho peregrino, mas sus respectivas claves
	 * secretas y firmas.
	 * @idHostel: Vector que contiene IDs de los albergues por los que paso el pregrino
	 * @publicKeyPilgrim: Clave publica del peregrino que se utiliza para desencriptar
	 * los datos del peregrino extraidos del mapa.
	 * @publicKeysHostel: Mapa que contiene las claves publicas de los albergues por los
	 * que ha pasado el peregrino. Se utilizan para desencriptar los datos de los albergues.  
	 */
	public void unpackCompostela(Map<String,byte[]> compostela,
			Vector<String> idHostel, PublicKey publicKeyPilgrim,
			Map<String, PublicKey> publicKeysHostel){
		
		this.dataPilgrim = compostela.get(Member.dataPilgrimCode);
		this.secretKeyPilgrim = compostela.get(Member.secretKeyPilgrimCode);
		this.signPilgrim = compostela.get(Member.signaturePilgrimCode);
		
		boolean verifyPilgrim = true;
		
		// Hostel
		String id;
		for(int i = 0; i < idHostel.size();i++){
			id = idHostel.get(i); 
			this.signHostel = compostela.get("HOSTEL_SIGNATURE"+id);
			this.dataHostel = compostela.get("HOSTEL_DATA"+id);
			this.secretKeyHostel = compostela.get("HOSTEL_SECRETKEY"+id);
			//Verify Sign
			if(this.verifySignHostel(publicKeysHostel.get(id))){
				System.out.println("Verified signature of hostel "+id);
				SecretKey secretKeyDecrypt = this.decryptSecretKey(this.secretKeyHostel);
				byte[] decryptDataHostel = this.decrytpData(dataHostel, secretKeyDecrypt);
				String str = new String(decryptDataHostel);
				System.out.println(str);
			} else {
				System.err.println("Error, invalid sign of hostel "+id);
				verifyPilgrim = false;
				break;
			}
		}

		//Pilgrim
		if(this.verifySignPilgrim(publicKeyPilgrim) && verifyPilgrim){
			System.out.println("Verified signature of pilgrim");
			SecretKey secretKeyDecrypt = this.decryptSecretKey(this.secretKeyPilgrim);
			byte[] decryptDataPilgrim = this.decrytpData(dataPilgrim, secretKeyDecrypt);
			String str = new String(decryptDataPilgrim);
			System.out.println(str);
		} else {
			System.err.println("Error, invalid sign of pilgrim");
		}
		
	}
	
	/*
	 * Metodo que se utiliza para verificar la firma del peregrino.
	 * @publicKey: Clave publica del peregrino
	 * @return boolean: Devuelve true si la firma del peregrino es correcta
	 * y false en caso contrario.
	 */
	private boolean verifySignHostel(PublicKey publicKey){
		boolean verifySign = false;
		try{
			Signature signature = Signature.getInstance(Member.signatureAlgorithm, Member.provider);
			signature.initVerify(publicKey);
			signature.update(this.signPilgrim);
			signature.update(this.dataHostel);
			verifySign = signature.verify(this.signHostel);
		}  catch (NoSuchAlgorithmException | NoSuchProviderException | 
				InvalidKeyException | SignatureException e) {
			System.err.println("Error in verify sign of hostel: " + e.getMessage());
		} 
		
		return verifySign;
	}
	
	/*
	 * Metodo que se utiliza para verificar la firma de los albergues.
	 * @publicKey: Clave publica del albergue
	 * @return boolean: Devuelve true si la firma del albergue es correcta
	 * y false en caso contrario.
	 */
	private boolean verifySignPilgrim(PublicKey publicKey){
		boolean verifySign = false;
		try{
			Signature signature = Signature.getInstance(Member.signatureAlgorithm,Member.provider);
			signature.initVerify(publicKey);
			signature.update(this.dataPilgrim);
			verifySign = signature.verify(this.signPilgrim);
		}  catch (NoSuchAlgorithmException | NoSuchProviderException |
				InvalidKeyException | SignatureException e) {
			System.err.println("Error in verify sign of Pilgrim: " + e.getMessage());
		} 
		
		return verifySign;
		
		
	}
	
	/*
	 * Metodo que se utiliza para desencriptar la clave secreta de los albergues 
	 * y del peregrino.
	 * @param cipherSecretKey: Clave secreta que se desea desencriptar
	 * @return SecretKey: Devuelve la clave secreta desencriptada en un array de bytes.   
	 */
	private SecretKey decryptSecretKey(byte[] cipherSecretKey) {
		byte[] buffer=null;
		SecretKey secretKey = null;
		try {
			Cipher cipher = Cipher.getInstance(Member.asymmetricCipher, Member.provider);
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			buffer = cipher.doFinal(cipherSecretKey);
			SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance(Member.symmetricCipher);
			DESKeySpec DESspec = new DESKeySpec(buffer);
			secretKey = secretKeyFactoryDES.generateSecret(DESspec);
		}
		catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
				InvalidKeySpecException | NoSuchAlgorithmException | 
				NoSuchProviderException | NoSuchPaddingException e) {
			System.err.println("Error in decrypt SecretKey: " + e.getMessage());
		} 
		
		return secretKey;
	}
	
	/*
	 * Metodo que se utiliza para desencriptar los datos de los albergues y del peregrino.
	 * @param cipherSecretKey: Clave secreta que se emplea para desencriptar los datos.
	 * @return SecretKey: Devuelve los datos desencriptados en un array de bytes.   
	 */
	private byte[] decrytpData(byte[] data, SecretKey secretKey){
		Cipher cipher;
		byte[] toret=null;
		
		try {
			cipher = Cipher.getInstance(Member.cipherMethod);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			toret = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |InvalidKeyException
				| IllegalBlockSizeException |BadPaddingException e) {
			System.err.println("Error in decrypt data: " + e.getMessage());
		} 
		return toret;
	}
}
