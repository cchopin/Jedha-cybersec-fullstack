#!/bin/bash
function draw_lizard() {
cat << 'EOF'
                       )/_
             _.--..---"-,--c_
        \L..'           ._O__)_
,-.     _.+  _  \..--( /
  `\.-''__.-' \ (     \_
    `'''       `\__   /\
                ')
EOF
}

function draw_toad() {
cat << 'EOF'
        @..@
       (----)
      ( >__< )
EOF
}

function draw_snake() {
cat << 'EOF'
                        _,.--.
    --..,_           .'`__ o  `;__,
       `'.'.       .'.'`  '---'`  '
          '.`-...-'.'
            `-...-'
EOF
}

function play()
{
read -p "Pick up a lizard (1), a toad (2), or a snake (3), q to quit: " player_choice
while [[ ! $player_choice =~ ^[1-3q]$ ]]; do
    echo "Invalid choice"
    read -p "Pick up a lizard (1), a toad (2), or a snake (3), q to quit: " player_choice
done

case $player_choice in
    1) draw_lizard ;;
    2) draw_toad ;;
    3) draw_snake ;;
    q) exit ;;
    *) echo "Invalid choice" ;;
esac

echo ""
echo ""
echo "computer pick up : "
echo ""
echo ""
computer_choice=$(( $RANDOM % 3 + 1 ))

case $computer_choice in
    1) draw_lizard ;;
    2) draw_toad ;;
    3) draw_snake ;;
esac

case "$player_choice-$computer_choice" in
    "1-3") echo "You win! Lizard ate Snake! 🦎" ;;
    "2-1") echo "You win! Toad ate Lizard! 🐸" ;;
    "3-2") echo "You win! Snake ate Toad! 🐍" ;;
    *) echo "Computer wins!" ;;
esac
echo ""
echo ""
}

while true
do
    play
done
