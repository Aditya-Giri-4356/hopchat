Output "assets/hopchat-demo.gif"

Set FontSize 12
Set Width 1280
Set Height 580
Set Padding 8
Set Theme "Catppuccin Mocha"
Set WindowBar "Colorful"
Set BorderRadius 8
Set TypingSpeed 45ms

# Prepare tmux dual terminal session (Left: Alice, Right: Bob)
Type "tmux kill-server 2>/dev/null; tmux new -s demo -d -x 158 -y 34 && tmux set -g status off && tmux split-window -h -t demo:0 -d && tmux attach -t demo"
Enter
Sleep 1.5s

# Left Terminal: Start Alice
Type "hopchat -u alice -p 9878 --no-bluetooth"
Enter
Sleep 2s

# Switch to Right Terminal: Start Bob
Ctrl+B
Type "o"
Sleep 0.5s
Type "hopchat -u bob -p 9879 --no-bluetooth"
Enter
Sleep 2.5s

# Switch to Left Terminal: Alice connects to Bob
Ctrl+B
Type "o"
Sleep 0.5s
Type "/connect 127.0.0.1 9879"
Enter
Sleep 2.5s

# Alice sends "HI"
Type "HI"
Enter
Sleep 2.5s

# Switch to Right Terminal: Bob replies "was up"
Ctrl+B
Type "o"
Sleep 0.5s
Type "was up"
Enter
Sleep 4.5s
