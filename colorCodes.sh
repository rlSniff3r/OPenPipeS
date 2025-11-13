#!/bin/bash

# colors
export RED=$'\033[0;31m'	  # ${RED}
export RED1=$'\033[1;31m'	  # ${RED}
export RED2=$'\033[2;31m'	  # ${RED}
export RED3=$'\033[3;31m'	  # ${RED}
export RED4=$'\033[4;31m'	  # ${RED}
export RED5=$'\033[5;31m'	  # ${RED}
export RED6=$'\033[6;31m'	  # ${RED}
export RED7=$'\033[7;31m'	  # ${RED}
export RED8=$'\033[8;31m'	  # ${RED}
export RED9=$'\033[9;31m'	  # ${RED}
export GREEN=$'\033[0;32m'	  # ${GREEN}
export GREEN1=$'\033[1;32m'	  # ${GREEN}
export GREEN2=$'\033[2;32m'	  # ${GREEN}
export GREEN3=$'\033[3;32m'	  # ${GREEN}
export GREEN4=$'\033[4;32m'	  # ${GREEN}
export GREEN5=$'\033[5;32m'	  # ${GREEN}
export GREEN6=$'\033[6;32m'	  # ${GREEN}
export GREEN7=$'\033[7;32m'	  # ${GREEN}
export GREEN8=$'\033[8;32m'	  # ${GREEN}
export GREEN9=$'\033[9;32m'	  # ${GREEN}
export YELLOW=$'\033[0;33m'	  # ${YELLOW}
export YELLOW1=$'\033[1;33m'	  # ${YELLOW}
export YELLOW2=$'\033[2;33m'	  # ${YELLOW}
export YELLOW3=$'\033[3;33m'	  # ${YELLOW}
export YELLOW4=$'\033[4;33m'	  # ${YELLOW}
export YELLOW5=$'\033[5;33m'	  # ${YELLOW}
export YELLOW6=$'\033[6;33m'	  # ${YELLOW}
export YELLOW7=$'\033[7;33m'	  # ${YELLOW}
export YELLOW8=$'\033[8;33m'	  # ${YELLOW}
export YELLOW9=$'\033[9;33m'	  # ${YELLOW}
export BLUE=$'\033[0;34m'	  # ${BLUE}
export BLUE1=$'\033[1;34m'	  # ${BLUE}
export BLUE2=$'\033[2;34m'	  # ${BLUE}
export BLUE3=$'\033[3;34m'	  # ${BLUE}
export BLUE4=$'\033[4;34m'	  # ${BLUE}
export BLUE5=$'\033[5;34m'	  # ${BLUE}
export BLUE6=$'\033[6;34m'	  # ${BLUE}
export BLUE7=$'\033[7;34m'	  # ${BLUE}
export BLUE8=$'\033[8;34m'	  # ${BLUE}
export BLUE9=$'\033[9;34m'	  # ${BLUE}
export MAGENTA=$'\033[0;35m'	  # ${MAGENTA}
export MAGENTA1=$'\033[1;35m'	  # ${MAGENTA}
export MAGENTA2=$'\033[2;35m'	  # ${MAGENTA}
export MAGENTA3=$'\033[3;35m'	  # ${MAGENTA}
export MAGENTA4=$'\033[4;35m'	  # ${MAGENTA}
export MAGENTA5=$'\033[5;35m'	  # ${MAGENTA}
export MAGENTA6=$'\033[6;35m'	  # ${MAGENTA}
export MAGENTA7=$'\033[7;35m'	  # ${MAGENTA}
export MAGENTA8=$'\033[8;35m'	  # ${MAGENTA}
export MAGENTA9=$'\033[9;35m'	  # ${MAGENTA}
export CYAN=$'\033[0;36m'	  # ${CYAN}
export CYAN1=$'\033[1;36m'	  # ${CYAN}
export CYAN2=$'\033[2;36m'	  # ${CYAN}
export CYAN3=$'\033[3;36m'	  # ${CYAN}
export CYAN4=$'\033[4;36m'	  # ${CYAN}
export CYAN5=$'\033[5;36m'	  # ${CYAN}
export CYAN6=$'\033[6;36m'	  # ${CYAN}
export CYAN7=$'\033[7;36m'	  # ${CYAN}
export CYAN8=$'\033[8;36m'	  # ${CYAN}
export CYAN9=$'\033[9;36m'	  # ${CYAN}
export WHITE=$'\033[0;37m'	  # ${WHITE}
export WHITE1=$'\033[1;37m'	  # ${WHITE}
export WHITE2=$'\033[2;37m'	  # ${WHITE}
export WHITE3=$'\033[3;37m'	  # ${WHITE}
export WHITE4=$'\033[4;37m'	  # ${WHITE}
export WHITE5=$'\033[5;37m'	  # ${WHITE}
export WHITE6=$'\033[6;37m'	  # ${WHITE}
export WHITE7=$'\033[7;37m'	  # ${WHITE}
export WHITE8=$'\033[8;37m'	  # ${WHITE}
export WHITE9=$'\033[9;37m'	  # ${WHITE}
export BLACK=$'\033[0;30m'		  # ${BLACK}
export BLACK1=$'\033[1;30m'		  # ${BLACK1}
export BLACK2=$'\033[2;30m'		  # ${BLACK}
export BLACK3=$'\033[3;30m'		  # ${BLACK}
export BLACK4=$'\033[4;30m'		  # ${BLACK}
export BLACK5=$'\033[5;30m'		  # ${BLACK}
export BLACK6=$'\033[6;30m'		  # ${BLACK}
export BLACK7=$'\033[7;30m'		  # ${BLACK}
export BLACK8=$'\033[8;30m'		  # ${BLACK}
export BLACK9=$'\033[9;30m'		  # ${BLACK}
export ORANGE=$'\033[0;33m'
export ORANGE1=$'\033[1;93m'
export ORANGE2=$'\033[2;93m'
export ORANGE3=$'\033[3;93m'
export ORANGE4=$'\033[4;93m'
export ORANGE5=$'\033[5;93m'
export ORANGE6=$'\033[6;93m'
export ORANGE7=$'\033[7;93m'
export ORANGE8=$'\033[8;93m'
export ORANGE9=$'\033[9;93m'

# Bold
# Value	Color
export BOLD_RED=$'\033[1;31m'	  # ${BOLD_RED}
export BOLD_GREEN=$'\033[1;32m'	  # ${BOLD_GREEN}
export BOLD_YELLOW=$'\033[1;33m'  # ${BOLD_YELLOW}
export BOLD_BLUE=$'\033[1;34m'	  # ${BOLD_BLUE}
export BOLD_MAGENTA=$'\033[1;35m' # ${BOLD_MAGENTA}
export BOLD_CYAN=$'\033[1;36m'	  # ${BOLD_CYAN}
export BOLD_WHITE=$'\033[1;37m'	  # ${BOLD_WHITE}

# underline, bold, italic
export UDLINE=$'\e[4m'		  # ${UDLINE}
export BOLD=$'\e[1m'		  # ${BOLD}
export ITALIC=$'\e[3m'		  # ${ITALIC}

# reset
export NC=$'\033[0m'		  # ${NC}

# Underline
# Value	Color
export UND_BLACK=$'\e[4;30m'
export UND_RED=$'\e[4;31m'
export UND_GREEN=$'\e[4;32m'
export UND_YELLOW=$'\e[4;33m'
export UND_BLUE=$'\e[4;34m'
export UND_PURPLE=$'\e[4;35m'
export UND_CYAN=$'\e[4;36m'
export UND_WHITE=$'\e[4;37m'

# Background
# Value		Color
export BG_BLACK=$'\e[40m'
export BG_RED=$'\e[41m'
export BG_GREEN=$'\e[42m'
export BG_YELLOW=$'\e[43m'
export BG_BLUE=$'\e[44m'
export BG_PURPLE=$'\e[45m'
export BG_CYAN=$'\e[46m'
export BG_WHITE=$'\e[47m'

# High Intensity
# Value		Color
export HI_BLACK=$'\e[0;90m'
export HI_BLACK5=$'\e[5;90m'
export HI_RED=$'\e[0;91m'
export HI_GREEN=$'\e[0;92m'
export HI_YELLOW=$'\e[0;93m'
export HI_BLUE=$'\e[0;94m'
export HI_PURPLE=$'\e[0;95m'
export HI_CYAN=$'\e[0;96m'
export HI_WHITE=$'\e[0;97m'

# Bold High Intensity
# Value	Color
export BOLD_HI_BLACK=$'\e[1;90m'
export BOLD_HI_RED=$'\e[1;91m'
export BOLD_HI_GREEN=$'\e[1;92m'
export BOLD_HI_YELLOW=$'\e[1;93m'
export BOLD_HI_BLUE=$'\e[1;94m'
export BOLD_HI_PURPLE=$'\e[1;95m'
export BOLD_HI_CYAN=$'\e[1;96m'
export BOLD_HI_WHITE=$'\e[1;97m'

# High Intenity backgrounds
# Value	Color
export BG_HI_BLACK=$'\e[0;100m'
export BG_HI_RED=$'\e[0;101m'
export BG_HI_GREEN=$'\e[0;102m'
export BG_HI_YELLOW=$'\e[0;103m'
export BG_HI_BLUE=$'\e[0;104m'
export BG_HI_CYAN=$'\e[0;106m'
export BG_HI_WHITE=$'\e[0;107m'
