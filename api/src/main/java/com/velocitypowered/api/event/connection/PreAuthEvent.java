/*
 * Copyright (C) 2018 Velocity Contributors
 *
 * The Velocity API is licensed under the terms of the MIT License. For more details,
 * reference the LICENSE file in the api top-level directory.
 */

 package com.velocitypowered.api.event.connection;

import java.security.KeyPair;
import java.util.UUID;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.event.annotation.AwaitingEvent;
import com.velocitypowered.api.proxy.InboundConnection;

import io.netty.channel.Channel;

import net.kyori.adventure.text.Component;
 /**
  * This event is fired once the player has been fully initialized and is about to connect to their
  * first server. Velocity will wait for this event to finish firing before it fires
  * {@link com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent} with any default
  * servers specified in the configuration, but you should try to limit the work done in any event
  * that fires during the login process.
  */
 @AwaitingEvent
 public final class PreAuthEvent {
 
   private String username;
   private Channel channel;
   private InboundConnection con;
   private UUID uuid;
   private final byte[] encryptedSharedSecret;
   private final byte[] encryptedVerifyToken;
   private SecretKey decryptedSharedSecret;
   private byte[] decryptedVerifyToken;
 
   private final KeyPair serverKeyPair;
   private PreAuthOverride override;
   private Component denyMessage = null;
 
   public PreAuthEvent(InboundConnection con, Channel channel, @Nullable String player, @Nullable UUID uuid, 
   byte[] sharedSecret, byte[] verifyToken, KeyPair serverKeyPair) {
     this.channel = channel;
     this.con = con;
     this.username = Preconditions.checkNotNull(player, "player");
     this.uuid = uuid;
     this.encryptedSharedSecret = Preconditions.checkNotNull(sharedSecret, "sharedSecret");
     this.encryptedVerifyToken = Preconditions.checkNotNull(verifyToken, "verifyToken");
     try{
       Cipher cipher = Cipher.getInstance("RSA");
       cipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
       this.decryptedSharedSecret = new SecretKeySpec(cipher.doFinal(encryptedSharedSecret), "AES");
       cipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
       this.decryptedVerifyToken = cipher.doFinal(encryptedVerifyToken);
     }catch(Exception e){
       e.printStackTrace();
     }
     
     this.serverKeyPair = Preconditions.checkNotNull(serverKeyPair, "serverKeyPair");      
     this.override = PreAuthOverride.MOJANG;
   }
 
   // MAY NOT HAVE BEEN ASIGNED YET IF MOJANG LOGIN
   @Nullable
   public String getUsername() {
     return username;
   }
 
   @Nullable
   public UUID getUniqueId() {
     return uuid;
   }
 
   public InboundConnection getConnection() {
     return con;
   }
 
   public void setUniqueId(UUID uuid) {
     this.uuid = uuid;
   }
 
   public void setUsername(String username) {
     this.username = username;
   }
 
   public void setDenyMessage(Component denyMessage) {
     this.denyMessage = denyMessage;
   }
 
   public byte[] getEncSharedSecret() {
     return encryptedSharedSecret;
   }
 
   public byte[] getEncVerifyToken() {
     return encryptedVerifyToken;
   }
 
   public SecretKey getDecSharedSecret() {
     return decryptedSharedSecret;
   }
 
   public byte[] getDecVerifyToken() {
     return decryptedVerifyToken;
   }
 
   public KeyPair getServerKeyPair() {
     return serverKeyPair;
   }
 
   public PreAuthOverride getOverride() {
     return override;
   }
 
   public Component getDenyMessage() {
     return denyMessage;
   }
   
   public void setOverride(PreAuthOverride override) {
     this.override = override;
   }
 
   public void setOverride(PreAuthOverride override, @Nullable Component message) {
     this.override = override;
     this.denyMessage = message;
   }
 
   @Override
   public String toString() {
     return "PreAuthEvent{"
       + "player=" + username
       + "sharedSecret=[REDACTED]"
       + "verifyToken=" + encryptedVerifyToken
       + "serverKeyPair=" + serverKeyPair
       + '}';
   }
 
   public static enum PreAuthOverride {
     MOJANG,
     BYPASS,
     DENY
   }
 }