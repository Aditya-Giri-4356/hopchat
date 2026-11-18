Output "assets/hopchat-demo.gif"

Set FontSize 14
Set Width 900
Set Height 560
Set Padding 10
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set BorderRadius 8
Set TypingSpeed 45ms

# Start HopChat as alice
Type "hopchat -u alice"
Enter
Sleep 3.5s

# Check Wi-Fi & LAN interface discovery
Type "/wifi"
Enter
Sleep 3s

# Check Bluetooth LE transport
Type "/bluetooth"
Enter
Sleep 3s

# Trigger the Interactive Subnet Scanner & Nearby peer sweep
Type "/scan"
Enter
Sleep 3.5s

# Close scanner overlay
Escape
Sleep 1.5s

# Send an authenticated, encrypted message
Type "Encrypted P2P message via X25519 & XChaCha20-Poly1305"
Enter
Sleep 3s

# Display the contextual help menu
Type "/help"
Enter
Sleep 3s

# Cleanly exit HopChat
Type "/quit"
Enter
Sleep 1.5s
