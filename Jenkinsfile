import org.jenkinsci.plugins.pipeline.modeldefinition.Utils

pipeline {
    agent { label 'IOSDEV' }

    triggers {
        gitlab(
            triggerOnNoteRequest: true
        )
        cron('H H * * *') //run at 23:30:00 
    }

    environment {
        KEYCHAIN_PASSWORD = credentials('KEYCHAIN_PASSWORD')

        CIBUILD = true 
    }

    options {
        ansiColor('xterm')
    }

    stages {
        stage('Fastlane cibuild') {
            steps {
                // Actual CI Build, Tests
                sh label: 'starting ios test run', script: '''#!/bin/bash -l
                    if [ -f $HOME/.bash_profile ]; then source $HOME/.bash_profile; fi

                    security -v unlock-keychain -p "${KEYCHAIN_PASSWORD}" ~/Library/Keychains/login.keychain

                    make cibuild
                    '''
            }
        }
    }

    post {
        failure {
            sendEMailNotification(getIOSDevEMailList())
        }
    }
}
