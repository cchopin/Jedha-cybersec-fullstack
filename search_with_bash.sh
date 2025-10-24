#!/bin/bash
# Usage: my_grep.sh <directory_name> <search_term>
# Example: my_grep.sh "/home/user" test

if [ $# -ne 2 ]; then
    echo "Usage: my_grep.sh <directory_name> <search_term>"
    exit 1
fi

directory_name="${1%/}"
search_term=$2
shopt -s nullglob

# Fonction pour afficher la barre de progression
show_progress() {
    local current=$1
    local total=$2
    local bar_length=50

    # Calculer le pourcentage et la longueur de la barre
    local percentage=$((current * 100 / total))
    local filled=$((current * bar_length / total))

    # Construire la barre
    local bar=""
    for ((i=0; i<filled; i++)); do
        bar+="█"
    done
    for ((i=filled; i<bar_length; i++)); do
        bar+="░"
    done

    # Afficher avec \r pour écraser la ligne précédente
    echo -ne "\r[$bar] $percentage% ($current/$total)"
}

# 1. Chercher des fichiers/directories qui matchent par NOM
dir_result=("$directory_name/"*"$search_term"*)

# Si des fichiers/directories trouvés par nom
if [ ${#dir_result[@]} -gt 0 ]; then
    pg_total=${#dir_result[@]}
    current=0

    echo "Searching files/directories by name..."

    # Barre de progression
    for item in "${dir_result[@]}"; do
        ((current++))
        show_progress $current $pg_total
        sleep 1
    done

    echo ""
    echo ""
    echo "===== Files/Directories found (by name) ====="
    echo ""
    for item in "${dir_result[@]}"; do
        basename "$item"
    done

# 2. Sinon chercher dans le CONTENU des fichiers
else
    # Compter les fichiers
    files=("$directory_name"/*)
    pg_total=0
    for item in "${files[@]}"; do
        if [ -f "$item" ]; then
            ((pg_total++))
        fi
    done

    if [ $pg_total -eq 0 ]; then
        echo "===== No files to search ====="
        exit 0
    fi

    echo "Searching in file contents..."
    current=0
    matched_files=()

    # Barre de progression pendant la recherche
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            ((current++))
            show_progress $current $pg_total

            # Vérifier si le fichier contient le terme
            if grep -q "$search_term" "$file" 2>/dev/null; then
                matched_files+=("$file")
            fi

            sleep 1
        fi
    done

    echo ""
    echo ""

    # Afficher les résultats
    if [ ${#matched_files[@]} -gt 0 ]; then
        echo "===== Files found (by content) ====="
        echo ""
        for file in "${matched_files[@]}"; do
            echo "File: $(basename "$file")"
            grep --color=always "$search_term" "$file"
            echo ""
        done
    else
        echo "===== No results found ====="
    fi
fi

