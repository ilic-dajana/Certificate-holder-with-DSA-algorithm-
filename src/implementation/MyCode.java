package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	private KeyStore myKeyStore;
	private char[] password = "root".toCharArray();
	private Enumeration<String> keyPairs; 

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}
	
	@Override
	public Enumeration<String> loadLocalKeystore() {
		
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			myKeyStore = KeyStore.getInstance("pkcs12", "BC");
			File fileKeyStore = new File("lokKeyStore.p12");
			if(fileKeyStore.exists()){
				FileInputStream fis = new FileInputStream("lokKeyStore.p12");
				myKeyStore.load(fis, password);
			}else{
				myKeyStore.load(null, null);
			}
			keyPairs = myKeyStore.aliases();
			return keyPairs;
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException e) {
			
			e.printStackTrace();
			System.out.println("Error: loadLocalKeystore");
		}
		
		return null;
	}
	public void resetLocalKeystore() {
		try {
			File fileKeyStore = new File("lokKeyStore.p12");
			fileKeyStore.delete();			
			fileKeyStore.createNewFile();
			myKeyStore.load(null, password);
			keyPairs=myKeyStore.aliases();
			
		} catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
			e.printStackTrace();
			System.out.println("Error: resetLocalKeystore");
		}	
		
	}
	
	private void addCertificateExtensions(X509v3CertificateBuilder certBuilder, X509Certificate cert) throws IOException{
		//******** SAN ********//
		String[] names = access.getAlternativeName(Constants.SAN);
		if(names.length > 0){
			boolean isCritical = access.isCritical(Constants.SAN);
			GeneralNamesBuilder SANbuilder = new GeneralNamesBuilder();
			for(int i = 0; i < names.length; i++)
				SANbuilder.addName(new GeneralName(GeneralName.dNSName, names[i]));
			certBuilder.addExtension(Extension.subjectAlternativeName, isCritical, SANbuilder.build());
		}
		//******** CP ********//
		byte[] extVal = cert.getExtensionValue(Extension.certificatePolicies.toString());
		if(extVal != null){
			boolean isCritical = access.isCritical(Constants.CP);
			CertificatePolicies cp = CertificatePolicies.getInstance(ASN1Primitive.fromByteArray(extVal));
			certBuilder.addExtension(Extension.certificatePolicies, isCritical, cp);
		}
		//******** EKU *******//
		boolean[] ekuval = access.getExtendedKeyUsage();
		
		boolean supported = access.isSupported(Constants.EKU);
		if(supported){
			//ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ASN1ObjectIdentifier.fromByteArray(extVal));
		}
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
			try {
				keypair_name = keypair_name.toLowerCase();
				
				if(myKeyStore.containsAlias(keypair_name))
					return false;
				
				if(access.getVersion() != Constants.V3)
					return false;
				
				if(access.getPublicKeyAlgorithm() != "DSA")
					return false;
				String subject = access.getSubject();
				String serial = access.getSerialNumber();
				BigInteger serialNmbr = new BigInteger(serial);
				X500NameBuilder builder = new X500NameBuilder();
				
				if(access.getSubjectCountry() != "")
					builder.addRDN(BCStyle.C, access.getSubjectCountry());
				if(access.getSubjectState() != "")
					builder.addRDN(BCStyle.ST, access.getSubjectState());
				if(access.getSubjectLocality() != "")
					builder.addRDN(BCStyle.L, access.getSubjectLocality());
				if(access.getSubjectOrganizationUnit() != "")
					builder.addRDN(BCStyle.OU, access.getSubjectOrganizationUnit());
				if(access.getSubjectOrganization() != "")
					builder.addRDN(BCStyle.O, access.getSubjectOrganization());
				if(access.getSubjectCommonName() != "")
					builder.addRDN(BCStyle.CN, access.getSubjectCommonName());
				
				X500Name X500name = builder.build();
				
				KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "BC");
				generator.initialize(Integer.parseInt(access.getPublicKeyParameter()), new SecureRandom());
				
				KeyPair keypair = generator.generateKeyPair();
				
				X509v3CertificateBuilder x509builder = new JcaX509v3CertificateBuilder(X500name, serialNmbr, access.getNotBefore(), access.getNotAfter(), X500name, keypair.getPublic());
				JcaContentSignerBuilder b = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm());
				b.setProvider("BC");
				ContentSigner signer = b.build(keypair.getPrivate());
				addCertificateExtensions(x509builder,  new JcaX509CertificateConverter().getCertificate(x509builder.build(signer)) );
				X509Certificate x500cert = new JcaX509CertificateConverter().getCertificate(x509builder.build(signer));
				
				X509Certificate[] chain = new X509Certificate[1];
				chain[0] = x500cert;
				myKeyStore.setKeyEntry(keypair_name, keypair.getPrivate(),password, chain);
				
				FileOutputStream fos = new FileOutputStream("lokKeyStore.p12");
				myKeyStore.store(fos, password);
				
				return myKeyStore.containsAlias(keypair_name);
			} catch (KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException | CertificateException | IOException e) {
				System.out.println("Error: saveKeypair");
				e.printStackTrace();
			}
		return false;
	}
	
	@Override
	public int loadKeypair(String keypair_name) {
			try {
				X509Certificate keypair = (X509Certificate) myKeyStore.getCertificate(keypair_name);
				String issuer = keypair.getIssuerX500Principal().getName(X500Principal.RFC1779);
				
				access.setVersion(keypair.getVersion()-1);
				access.setSerialNumber(keypair.getSerialNumber().toString() + "    " + issuer.toString());
				System.out.println(keypair.getSubjectX500Principal().getName(X500Principal.RFC1779));
				access.setSubject(keypair.getSubjectX500Principal().getName(X500Principal.RFC1779));
				access.setIssuer(issuer);
				access.setSubjectSignatureAlgorithm(keypair.getPublicKey().getAlgorithm());
				access.setIssuerSignatureAlgorithm(keypair.getSigAlgName());
				access.setNotAfter(keypair.getNotAfter());
				access.setNotBefore(keypair.getNotBefore());
				
				/*Set<String> extOIDs = keypair.getCriticalExtensionOIDs();

					for(int i = 0; i < extOIDs.size(); i++){
						if(extOIDs.equals(Extension.certificatePolicies.toString()))
							access.setCritical(Constants.CP, true);
						
						if(extOIDs.equals(Extension.extendedKeyUsage.toString()))
							access.setCritical(Constants.EKU, true);
						
						if(extOIDs.equals(Extension.subjectAlternativeName.toString()))
							access.setCritical(Constants.SAN, true);
					}
					*/
				if(keypair.getSubjectX500Principal().equals(issuer))
					return 0;
				if(myKeyStore.isKeyEntry(keypair_name))
					return 2;
				
				return 1;
				
			} catch (KeyStoreException e) {
				e.printStackTrace();
				System.out.println("Error: loadKeypair");
				return -1;

			}
	}
	
	@Override
	public boolean importKeypair(String keypair_name, String file, String password_t) {
		try {
			FileInputStream fis = new FileInputStream(file);
			KeyStore temp = KeyStore.getInstance("pkcs12", "BC");
			temp.load(fis, password_t.toCharArray());
			if(myKeyStore.containsAlias(keypair_name) || !temp.containsAlias(keypair_name))
				return false;
			Enumeration<String> alijasi = temp.aliases();
			boolean find = false;
			
			while(alijasi.hasMoreElements()){
				String curr = alijasi.nextElement();
				if(curr.equals(keypair_name)){
					myKeyStore.setKeyEntry(keypair_name, temp.getKey(keypair_name, password_t.toCharArray()), password_t.toCharArray(), temp.getCertificateChain(keypair_name));
					find = true;
					break;
				}
			}
			FileOutputStream fos = new FileOutputStream("lokKeyStore.p12");
			myKeyStore.store(fos, password);
			return find;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
			myKeyStore.deleteEntry(keypair_name);
			FileOutputStream fos = new FileOutputStream("lokKeyStore");
			myKeyStore.store(fos, password);
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			System.out.println("Error: removeKeypair");
			return false;
		}
	}
	
	@Override
	public boolean exportKeypair(String keypair_name, String file, String password_t) {
		try {
			KeyStore temp = KeyStore.getInstance("pkcs12", "BC");
			temp.load(null, password_t.toCharArray());
			Key key = myKeyStore.getKey(keypair_name, password);
			java.security.cert.Certificate[] chain = myKeyStore.getCertificateChain(keypair_name);
			
			temp.setKeyEntry(keypair_name, key,password_t.toCharArray(), chain);
			
			FileOutputStream fos = new FileOutputStream(file);
			temp.store(fos, password_t.toCharArray());
			fos.close();
			return true;
			
		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		
		return false;
	}
//***********************************************************	
	@Override
	public boolean canSign(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		// TODO Auto-generated method stub
		return false;
	}



	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}



	
	

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
