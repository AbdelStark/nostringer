import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import {
  generateSecretKey,
  getPublicKey as nostrGetPublicKey,
} from "nostr-tools";
import { bytesToHex } from "@noble/hashes/utils";

// Helper function to convert Uint8Array to hex string
function uint8ArrayToHex(array: Uint8Array): string {
  return bytesToHex(array);
}

// Simulate a real-world Nostr scenario with ring signatures

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig?: string;
  ringSignature?: {
    c0: string;
    s: string[];
    ring: string[];
  };
}

describe("Nostr Real-World Integration Tests", () => {
  // Simulate authenticating a nostr event with ring signature instead of normal signature
  test("Anonymous event creation with ring signatures", () => {
    // Create a group of developers allowed to post reviews anonymously
    const authorizedDevelopers = Array.from({ length: 5 }, () => {
      const sk = generateSecretKey();
      return {
        privateKey: sk,
        publicKey: nostrGetPublicKey(sk),
        name: `dev-${Math.floor(Math.random() * 1000)}`, // Simulated developer name
      };
    });

    // Extract just the public keys for the ring
    const developerRing = authorizedDevelopers.map((dev) => dev.publicKey);

    // Choose one developer to create a review
    const authorIndex = 2; // The third developer
    const author = authorizedDevelopers[authorIndex];

    // Create a review event
    const reviewContent = "This app is great but has some privacy concerns.";

    // Create an unsigned event (standard Nostr format)
    const event: NostrEvent = {
      id: "placeholder", // Would normally be the hash of the event
      pubkey: "anonymous", // We're hiding the actual author
      created_at: Math.floor(Date.now() / 1000),
      kind: 1001, // Custom kind for anonymous reviews
      tags: [
        ["g", "reviews"],
        ["ring", ...developerRing], // Include the ring of authorized reviewers
      ],
      content: reviewContent,
    };

    // Instead of a normal signature, create a ring signature
    const message = JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);

    // Sign with the chosen developer's key
    const skHex = uint8ArrayToHex(author.privateKey);
    const ringSignature = sign(message, skHex, developerRing);

    // Attach the ring signature to the event
    event.ringSignature = {
      c0: ringSignature.c0,
      s: ringSignature.s,
      ring: developerRing,
    };

    // Verify the event with the ring signature
    const isValid = verify(ringSignature, message, developerRing);
    expect(isValid).toBe(true);

    // A verifier can check that the signature comes from one of the authorized developers
    // but cannot determine which one specifically

    // Create a modified message
    const tamperedEvent = { ...event, content: "Modified content" };
    const tamperedMessage = JSON.stringify([
      0,
      tamperedEvent.pubkey,
      tamperedEvent.created_at,
      tamperedEvent.kind,
      tamperedEvent.tags,
      tamperedEvent.content,
    ]);

    // Verify the signature should fail for tampered content
    const isTamperedValid = verify(
      ringSignature,
      tamperedMessage,
      developerRing
    );
    expect(isTamperedValid).toBe(false);
  });

  test("Anonymous voting with multiple rings", () => {
    // Create multiple voting rings for different groups

    // Board members group
    const boardMembers = Array.from({ length: 3 }, () => {
      const sk = generateSecretKey();
      return { privateKey: sk, publicKey: nostrGetPublicKey(sk) };
    });
    const boardRing = boardMembers.map((m) => m.publicKey);

    // Advisory committee group
    const advisoryCommittee = Array.from({ length: 4 }, () => {
      const sk = generateSecretKey();
      return { privateKey: sk, publicKey: nostrGetPublicKey(sk) };
    });
    const advisoryRing = advisoryCommittee.map((m) => m.publicKey);

    // Voting topic
    const votingTopic = "Should we implement feature X?";

    // Board member #1 votes YES
    const sk1Hex = uint8ArrayToHex(boardMembers[0].privateKey);
    const boardVote1 = sign(`VOTE:YES:${votingTopic}`, sk1Hex, boardRing);

    // Board member #2 votes NO
    const sk2Hex = uint8ArrayToHex(boardMembers[1].privateKey);
    const boardVote2 = sign(`VOTE:NO:${votingTopic}`, sk2Hex, boardRing);

    // Advisory member #3 votes YES
    const sk3Hex = uint8ArrayToHex(advisoryCommittee[2].privateKey);
    const advisoryVote = sign(`VOTE:YES:${votingTopic}`, sk3Hex, advisoryRing);

    // Verify all votes are valid in their respective rings
    expect(verify(boardVote1, `VOTE:YES:${votingTopic}`, boardRing)).toBe(true);
    expect(verify(boardVote2, `VOTE:NO:${votingTopic}`, boardRing)).toBe(true);
    expect(verify(advisoryVote, `VOTE:YES:${votingTopic}`, advisoryRing)).toBe(
      true
    );

    // Verify votes don't validate in the wrong ring
    expect(verify(boardVote1, `VOTE:YES:${votingTopic}`, advisoryRing)).toBe(
      false
    );
    expect(verify(advisoryVote, `VOTE:YES:${votingTopic}`, boardRing)).toBe(
      false
    );

    // The votes are unlinkable - we can count YES vs NO votes but can't determine who voted what
    // All we know is that the votes came from authorized members
  });

  test("Private group messaging with ring authentication", () => {
    // Create a private group with several members
    const groupMembers = Array.from({ length: 5 }, () => {
      const sk = generateSecretKey();
      return {
        privateKey: sk,
        publicKey: nostrGetPublicKey(sk),
        name: `user-${Math.floor(Math.random() * 1000)}`,
      };
    });

    const groupRing = groupMembers.map((m) => m.publicKey);

    // One member sends a message to the group
    const senderIndex = 1;
    const sender = groupMembers[senderIndex];
    const messageContent =
      "Hey everyone, what do you think about the latest proposal?";

    // Create a message with ring signature to hide which specific member sent it
    const message = JSON.stringify({
      group_id: "private-group-xyz",
      timestamp: new Date().toISOString(),
      content: messageContent,
    });

    const skHex = uint8ArrayToHex(sender.privateKey);
    const messageSignature = sign(message, skHex, groupRing);

    // Group members can verify the message is from a group member
    // without knowing specifically which member sent it
    expect(verify(messageSignature, message, groupRing)).toBe(true);

    // Someone outside the group tries to forge a message with their key
    const outsider = generateSecretKey();
    const outsiderPk = nostrGetPublicKey(outsider);

    // They'd need to include their key in the ring to create a valid signature
    const compromisedRing = [...groupRing, outsiderPk];
    const forgedMessage = JSON.stringify({
      group_id: "private-group-xyz",
      timestamp: new Date().toISOString(),
      content: "Forged message from outsider",
    });

    const outsiderSkHex = uint8ArrayToHex(outsider);
    const forgedSignature = sign(forgedMessage, outsiderSkHex, compromisedRing);

    // But this would fail verification against the original group ring
    expect(verify(forgedSignature, forgedMessage, groupRing)).toBe(false);

    // The group would verify against their known ring, not the compromised one
    // So the outsider can't send messages that appear to come from the group
  });
});
