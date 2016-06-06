package org.shu.zq.crypto

import java.io._
import java.security.interfaces.RSAPublicKey
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{Key, KeyFactory, PrivateKey}

import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.openssl.PKCS8Generator
import org.bouncycastle.openssl.jcajce.{JcaPKCS8Generator, JceOpenSSLPKCS8EncryptorBuilder}
import org.bouncycastle.util.io.pem.{PemReader, PemObject, PemWriter}
;
/**
  * Created by Qiang on 3/20/2016.
  */
object KeyPersistence {

  val PUBLIC_DESC = "RSA PUBLIC KEY"
  val PRIVATE_DESC = "RSA PRIVATE KEY"

  def write(fileName: String, desc : String, key : Key) = {
    writePem(new FileOutputStream(fileName), desc, key.getEncoded)
  }

  def write(fileName: String, key : PrivateKey, password : String) = {
    writePem(new FileOutputStream(fileName), key, password)
  }

  def readPublicKey(fileName: String) : RSAPublicKey = {
    return readPemPublicKey(new FileReader(new File(fileName)))
  }

  def readPrivateKey(fileName: String) : RSAPrivateKey = {
    return readPemPrivateKey(new FileReader(new File(fileName)))
  }

  def writePem(out: OutputStream , key : PrivateKey, password : String) = {
    val outWriter = new OutputStreamWriter(out)
    val encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES)
    encryptorBuilder.setPasssword(password.toCharArray())

    using (new PemWriter(outWriter)) { pemWriter =>
      val outputEncryptor = encryptorBuilder.build()
      val generator = new JcaPKCS8Generator(key, outputEncryptor)

      val pemObject = generator.generate()
      pemWriter.writeObject(pemObject)
    }
  }

  private def writePem(out: OutputStream, desc : String, content : Array[Byte]) = {
    val writer = new OutputStreamWriter(out)
    val pemObject = new PemObject(desc, content)

    using(new PemWriter(writer)){ wtr =>
      wtr.writeObject(pemObject)
    }
  }

  def readPem(reader: InputStreamReader): Array[Byte] =   {
    return new PemReader(reader).readPemObject().getContent()
  }

  def readPemPublicKey(reader: InputStreamReader): RSAPublicKey = {
    val factory = KeyFactory.getInstance(KeyGenerator.ALGORITHM, KeyGenerator.PROVIDER);
    return factory.generatePublic(new X509EncodedKeySpec(readPem(reader))).asInstanceOf[RSAPublicKey]
  }

  def readPemPrivateKey(reader: FileReader): RSAPrivateKey = {
    val factory = KeyFactory.getInstance(KeyGenerator.ALGORITHM, KeyGenerator.PROVIDER)
    return factory.generatePrivate(new PKCS8EncodedKeySpec(readPem(reader))).asInstanceOf[RSAPrivateKey]
  }

  def using[T <: { def close() }]
  (resource: T)
  (block: T => Unit)
  {
    try {
      block(resource)
    } finally {
      if (resource != null) resource.close()
    }
  }
}
