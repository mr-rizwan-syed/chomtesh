#!/bin/bash
#title: CHOMTE.SH - active_recon
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Reconnaisance Scans
#author:        mr-rizwan-syed
#==============================================================================

function techdetect(){
    # echo $tech $httpxout.json $$results/httpxmerge.csv

    [ -e $results/httpxmerge.csv ] && urls=($(csvcut -c url,tech $results/httpxmerge.csv 2>/dev/null | grep -i $1 | cut -d ',' -f 1))
    [ -e $httpxout.json ] && urls+=($(cat $httpxout.json | jq -r 'select(.tech // [] | length > 0) | [.url, .tech[]] | @csv' | grep -i $1 | cut -d , -f 1 | tr -d '"'))
    [ -e $webtech ] && urls+=($(cat $webtech | jq -r '. | [.hostname, .matches[].app_name] | @csv' | grep -i $1 | cut -d , -f 1 | tr -d '"'))

    result=$(printf "%s\n" "${urls[@]}")
    for url in $result; do
        echo $url | grep -oE "^https?://[^/]*(:[0-9]+)?"
    done
}

function active_recon(){
    
    # techdetect function can be use to run with manual tools; see below examples; altough nuclei has automatic-scan feature now.
    
    wordpress_recon(){
       [[ $(techdetect Wordpress) ]] | anew $enumscan/wordpress_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/wordpress_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/wordpress_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Wordpress Recon\n${NC}"
            [ ! -e $enumscan/wordpress_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/wordpress_urls.txt -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -o $enumscan/wordpress_nuclei_results.txt \n${NC}"
            [ ! -e $enumscan/wordpress_nuclei_results.txt ] && nuclei -l $enumscan/wordpress_urls.txt -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -o $enumscan/wordpress_nuclei_results.txt
        #   [ ! -e $enumscan/*_wpscan_result.txt ] && interlace -tL $enumscan/wordpress_urls.txt -threads 5 -c "wpscan --url _target_ $wpscan_flags -o $enumscan/_cleantarget_wpscan_result.txt"
            echo -e "WordPress Recon: [$(cat $enumscan/wordpress_urls.txt | wc -l)]"
        fi
    }

    joomla_recon(){
        [[ $(techdetect Joomla) ]] | anew $enumscan/joomla_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/joomla_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/joomla_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Joomla Recon\n${NC}"
            [ ! -e $enumscan/joomla_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/joomla_urls.txt -w ~/nuclei-templates/workflows/joomla-workflow.yaml -o $enumscan/joomla_nuclei_results.txt\n${NC}"
            [ ! -e $enumscan/joomla_nuclei_results.txt ] && nuclei -l $enumscan/joomla_urls.txt -w ~/nuclei-templates/workflows/joomla-workflow.yaml -o $enumscan/joomla_nuclei_results.txt
            echo -e "Joomla Recon: [$(cat $enumscan/joomla_urls.txt | wc -l)]"
        fi
    }

    drupal_recon(){
        [[ $(techdetect Drupal) ]] | anew $enumscan/drupal_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/drupal_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/drupal_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Drupal Recon\n${NC}"
            [ ! -e $enumscan/drupal_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/drupal_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/drupal_nuclei_results.txt\n${NC}"
            [ ! -e $enumscan/drupal_nuclei_results.txt ] && nuclei -l $enumscan/drupal_urls.txt -w ~/nuclei-templates/workflows/drupal-workflow.yaml -o $enumscan/drupal_nuclei_results.txt
            echo -e "Drupal Recon: [$(cat $enumscan/drupal_urls.txt | wc -l)]"
        fi
    }

    jira_recon(){
        [[ $(techdetect Jira) ]] | anew $enumscan/jira_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/jira_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/jira_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Jira Recon\n${NC}"
            [ ! -e $enumscan/jira_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/jira_urls.txt -w ~/nuclei-templates/workflows/jira-workflow.yaml -o $enumscan/jira_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/jira_nuclei_results.txt ] && nuclei -l $enumscan/jira_urls.txt -w ~/nuclei-templates/workflows/jira-workflow.yaml -o $enumscan/jira_nuclei_results.txt
            echo -e "Jira Recon: [$(cat $enumscan/jira_urls.txt | wc -l)]"
        fi
    }

    jenkins_recon(){
        [[ $(techdetect Jenkins) ]] | anew $enumscan/jenkins_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/jenkins_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/jenkins_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Jenkins Recon\n${NC}"
            [ ! -e $enumscan/jenkins_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/jenkins_urls.txt -w ~/nuclei-templates/workflows/jenkins-workflow.yaml -o $enumscan/jenkins_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/jenkins_nuclei_results.txt ] && nuclei -l $enumscan/jenkins_urls.txt -w ~/nuclei-templates/workflows/jenkins-workflow.yaml -o $enumscan/jenkins_nuclei_results.txt
            echo -e "Jenkins Recon: [$(cat $enumscan/jenkins_urls.txt | wc -l)]"
        fi
    }

    azure_recon(){
        [[ $(techdetect Azure) ]] | anew $enumscan/azure_urls.txt -q &>/dev/null 2>&1
        if [ -s $enumscan/azure_urls.txt ];then
            echo -e ""
            [ ! -e $enumscan/azure_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running Azure Recon\n${NC}"
            [ ! -e $enumscan/azure_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/azure_urls.txt -w ~/nuclei-templates/workflows/azure-workflow.yaml -o $enumscan/azure_nuclei_results.txt\n${NC}" 
            [ ! -e $enumscan/azure_nuclei_results.txt ] && nuclei -l $enumscan/azure_urls.txt -w ~/nuclei-templates/workflows/azure-workflow.yaml -o $enumscan/azure_nuclei_results.txt
            echo -e "Azure Recon: [$(cat $enumscan/azure_urls.txt | wc -l)]"
        fi
    }

    S3_recon(){
        [[ $(techdetect S3) ]] | anew $enumscan/s3_urls.txt -q &>/dev/null 2>&1
            if [ -s $enumscan/s3_urls.txt ];then
                echo -e ""
                [ ! -e $enumscan/s3_nuclei_results.txt ] && echo -e "${YELLOW}[*] Running S3 Recon\n${NC}"
                [ ! -e $enumscan/s3_nuclei_results.txt ] && echo -e "${BLUE}[*] nuclei -l $enumscan/s3_urls.txt -tags s3 -o $enumscan/s3_nuclei_results.txt\n${NC}" 
                [ ! -e $enumscan/s3_nuclei_results.txt ] && nuclei -l $enumscan/s3_urls.txt -tags s3 -o $enumscan/s3_nuclei_results.txt
                echo -e "S3 URLs: [$(cat $enumscan/s3_urls.txt | wc -l)]"
            fi
    }
    
    

    wordpress_recon 2>/dev/null
    joomla_recon 2>/dev/null
    drupal_recon 2>/dev/null
    jira_recon 2>/dev/null
    jenkins_recon 2>/dev/null
    azure_recon 2>/dev/null
    S3_recon 2>/dev/null

   

 
}
