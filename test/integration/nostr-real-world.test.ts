import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import { NostrTools } from "../helpers";

// Debug function to inspect keys and signatures
function debugLog(label: string, data: any) {
  console.log(`\n------ ${label} ------`);
  console.log(data);
  console.log("-".repeat(label.length + 14));
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
    const authorizedDevelopers = NostrTools.generateKeyPairs(3);

    // Add developer names for the simulation
    const developers = authorizedDevelopers.map((dev, i) => ({
      ...dev,
      name: `dev-${i + 1}`,
    }));

    // Extract just the public keys for the ring
    const developerRing = NostrTools.getPublicKeys(developers);
    debugLog("Developer Ring", developerRing);

    // Choose one developer to create a review
    const authorIndex = 1; // The second developer
    const author = developers[authorIndex];

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

    debugLog("Message to sign", message);

    // Sign with the chosen developer's key
    const ringSignature = sign(message, author.privateKeyHex, developerRing);
    debugLog("Ring Signature", ringSignature);

    // Attach the ring signature to the event
    event.ringSignature = {
      c0: ringSignature.c0,
      s: ringSignature.s,
      ring: developerRing,
    };

    // Verify the signature
    const isValid = verify(ringSignature, message, developerRing);
    expect(isValid).toBe(true);

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
      developerRing,
    );
    expect(isTamperedValid).toBe(false);
  });

  test("Anonymous voting with multiple rings", () => {
    // This test illustrates how ring signatures can be used for anonymous voting
    // across different groups, each with their own ring

    // Board member group
    const boardMembers = NostrTools.generateKeyPairs(2);
    const boardRing = NostrTools.getPublicKeys(boardMembers);

    // Advisory committee group
    const advisors = NostrTools.generateKeyPairs(2);
    const advisorRing = NostrTools.getPublicKeys(advisors);

    // Create a vote message
    const voteMessage = "VOTE: Feature X";

    // Create signatures for each group
    const boardSignature = sign(
      voteMessage,
      boardMembers[0].privateKeyHex,
      boardRing,
    );
    const advisorSignature = sign(
      voteMessage,
      advisors[0].privateKeyHex,
      advisorRing,
    );

    // Demonstrate that signatures don't verify with the wrong ring
    // Board signature should not verify with advisor ring
    const boardSigWithAdvisorRing = verify(
      boardSignature,
      voteMessage,
      advisorRing,
    );
    expect(boardSigWithAdvisorRing).toBe(false);

    // Advisor signature should not verify with board ring
    const advisorSigWithBoardRing = verify(
      advisorSignature,
      voteMessage,
      boardRing,
    );
    expect(advisorSigWithBoardRing).toBe(false);
  });

  test("Private group messaging security", () => {
    // This test demonstrates why ring signatures are secure for group messaging

    // Create a private group with several members
    const groupMembers = NostrTools.generateKeyPairs(3);
    const groupRing = NostrTools.getPublicKeys(groupMembers);

    // Create an outsider who is not part of the group
    const outsider = NostrTools.generateKeyPair();

    // The outsider creates a compromised ring that includes their key
    const compromisedRing = [...groupRing, outsider.publicKeyHex];

    // Message content
    const messageContent = "Secret group information";

    // Outsider attempts to create a signature
    const forgedSignature = sign(
      messageContent,
      outsider.privateKeyHex,
      compromisedRing,
    );

    // But when verifying against the original group ring (without the outsider),
    // the signature will fail verification
    const isValid = verify(forgedSignature, messageContent, groupRing);
    expect(isValid).toBe(false);

    // This shows that members of the group can verify messages came from within
    // the group by checking against their known group ring
  });
});
