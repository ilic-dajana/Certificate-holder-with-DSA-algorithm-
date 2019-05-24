package implementation;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	private KeyStore myKeyStore;
	private char[] password = "root".toCharArray();
	private Enumeration<String> keyPairs; 
	private File fileKeyStore = new File("lokKeyStore.p12");
	
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		Security.addProvider(new BouncyCastleProvider());
	}
	
//******************************************************KEYSTORE METHODS***************************************************************
	@Override
	public Enumeration<String> loadLocalKeystore() {	
		try {
			myKeyStore = KeyStore.getInstance("pkcs12");
			File fileKeyStore = new File("lokKeyStore.p12");
			if(fileKeyStore.exists()){
				FileInputStream fis = new FileInputStream(fileKeyStore);
				myKeyStore.load(fis, password);
				fis.close();
			}else{
				myKeyStore.load(null, null);
			}
			keyPairs = myKeyStore.aliases();
			return keyPairs;
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
			
			e.printStackTrace();
			System.out.println("Error: loadLocalKeystore");
		}
		
		return null;
	}
	public void resetLocalKeystore() {
		try {
			myKeyStore = KeyStore.getInstance("pkcs12");
			myKeyStore.load(null, password);
			keyPairs=null;
			FileOutputStream fos = new FileOutputStream(fileKeyStore);
			myKeyStore.store(fos, password);
			fos.close();
		} catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
			e.printStackTrace();
			System.out.println("Error: resetLocalKeystore");
		}	
		
	}
	
//******************************************************KEYPAIR METHODS***************************************************************

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
				
				FileOutputStream fos = new FileOutputStream(fileKeyStore);
				myKeyStore.store(fos, password);
				fos.close();
				
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
				String issuer = keypair.getIssuerX500Principal().getName(X500Principal.RFC2253);
				
				access.setVersion(keypair.getVersion()-1);
				access.setSerialNumber(keypair.getSerialNumber().toString());
				access.setSubject(keypair.getSubjectX500Principal().getName(X500Principal.RFC2253));
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
				if(keypair.getSubjectX500Principal().equals(keypair.getIssuerX500Principal()))
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
			FileOutputStream fos = new FileOutputStream(fileKeyStore);
			myKeyStore.store(fos, password);
			fos.close();
			return find;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | NoSuchProviderException | UnrecoverableKeyException e) {
			e.printStackTrace();
			System.out.println("Error: importKeypair");
		}
		
		return false;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
			myKeyStore.deleteEntry(keypair_name);
			FileOutputStream fos = new FileOutputStream(fileKeyStore);
			myKeyStore.store(fos, password);
			fos.close();
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
			System.out.println("Error: exportKeypair");
			return false;
		}
		
	}
	
//******************************************************SIGN CHECK METHOD ***************************************************************

	@Override
	public boolean canSign(String keypair_name) {
		try {
			X509Certificate certificate = (X509Certificate) myKeyStore.getCertificate(keypair_name);			
			
			if(certificate.getBasicConstraints() == -1){ // notCA
				return false;
			}
			boolean[] keyusage = certificate.getKeyUsage();
				if(keyusage == null)
					return true;
			
			return keyusage[5];		 // keyusage[5] - cert signing		
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			System.out.println("Error: canSign");
			return false;
		}
	}

//******************************************************CERTIFICATE METHODS***************************************************************
	
	@Override
	public boolean importCertificate(String file, String keypair_name) {
		try {
						
			if(myKeyStore.containsAlias(keypair_name))
				return false;
			
			FileInputStream fis = new FileInputStream(file);
			
			X509Certificate certificate =  (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
			
			myKeyStore.setCertificateEntry(keypair_name, certificate);
			
			FileOutputStream fos = new FileOutputStream(fileKeyStore);
			myKeyStore.store(fos, password);
			
			fis.close();
			fos.close();
			return true;
		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
			System.out.println("Error: importCertificate");
		}
		
		return false;
	}
	
	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
			FileOutputStream fos;	
			switch(encoding){			
			case Constants.DER:
			{
				if( format == Constants.HEAD){
					try {
						java.security.cert.Certificate cert = myKeyStore.getCertificate(keypair_name);				
						fos = new FileOutputStream(file);
						fos.write(cert.getEncoded());				
						fos.flush();
					} catch (KeyStoreException | CertificateEncodingException | IOException e) {
						e.printStackTrace();
					}
					
				}else if(format == Constants.CHAIN){					
					return false;
				}
				break;
			}
			case Constants.PEM:
			{
				if(format == Constants.HEAD ){
					try {
						java.security.cert.Certificate cer = myKeyStore.getCertificate(keypair_name);
						fos = new FileOutputStream(file);
						OutputStreamWriter osw = new OutputStreamWriter(fos);
						JcaPEMWriter pemWriter = new JcaPEMWriter(osw);
						
						pemWriter.writeObject(cer);
						pemWriter.flush();
						pemWriter.close();
					} catch (KeyStoreException | IOException e) {
						e.printStackTrace();
					}
					
				}else if (format == Constants.CHAIN) {
					try {
						java.security.cert.Certificate[] chain = myKeyStore.getCertificateChain(keypair_name);
						if(chain != null){
							fos = new FileOutputStream(file);
							OutputStreamWriter osw = new OutputStreamWriter(fos);
							JcaPEMWriter pemWriter = new JcaPEMWriter(osw);
							
							for(int i = 0; i < chain.length; i++){
								pemWriter.writeObject(chain[i]);
							}
							pemWriter.flush();
							pemWriter.close();
						}
					} catch (KeyStoreException | IOException e) {
						e.printStackTrace();
					}
					
				}
				break;
			}
			}
		return true;
}
	

//******************************************************DESCRIBES METHODS***************************************************************

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		try {
			X509Certificate keypair = (X509Certificate) myKeyStore.getCertificate(keypair_name);
			PublicKey publicKey = keypair.getPublicKey();
			
			if(publicKey instanceof DSAPublicKey){
				DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
				return Integer.toString(dsaKey.getY().bitLength());
			}
			
			return null;
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		try {
			X509Certificate keypair = (X509Certificate) myKeyStore.getCertificate(keypair_name);
			
			String[] attributes = keypair.getSubjectDN().toString().split(",");
			StringBuilder builder = new StringBuilder();
			for(int i =0; i< attributes.length ;i++){
				builder.append(attributes[i].trim());
				if( i!= attributes.length - 1) builder.append(",");
			}
			
			return  builder.toString();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {

		try {
			X509Certificate keypair = (X509Certificate) myKeyStore.getCertificate(keypair_name);
			return keypair.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

//******************************************************CA METHOD***************************************************************
	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			FileInputStream fis = new FileInputStream(file);
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			DataInputStream dis = new DataInputStream(fis);
			
			CMSSignedData cms = new CMSSignedData(fis);
			Collection<X509Certificate> collection = (Collection<X509Certificate>) fact.generateCertificate(dis);
			
			Store<X509CertificateHolder> temp_store = cms.getCertificates();
			Collection<X509CertificateHolder> cert_holders = temp_store.getMatches(null);
			X509Certificate[] chain = new X509Certificate[cert_holders.size()];
			int i = 0;
			for(X509CertificateHolder t: cert_holders){
				chain[i++] = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(t);
			}
			
			myKeyStore.setKeyEntry(keypair_name, myKeyStore.getKey(keypair_name, password), password,  chain);
			
			FileOutputStream fos = new FileOutputStream(fileKeyStore);
			myKeyStore.store(fos, password);
			
			fos.close();
			fis.close();
			dis.close();
			return true;
		} catch (CertificateException | IOException | CMSException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.out.println("Error: importCAReply");
		}
		
		return false;
	}
	
//******************************************************CSR METHODS***************************************************************
	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}
	
	@Override
	public String importCSR(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	

	

}
