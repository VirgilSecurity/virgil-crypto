#!groovy
stage 'Grab SCM'

node('master') {
    clearContentUnix()
    checkout scm
    sh 'mkdir -p install'
    sh 'cp -f VERSION install/'
    archiveArtifacts('install/VERSION')
    stash includes: '**', name: 'src'
}

stage 'Build'

def slaves = [:]
slaves['native-centos7'] = createNativeUnixBuild('build-centos7');
slaves['native-os-x'] = createNativeUnixBuild('build-os-x');
slaves['native-win8'] = createNativeWindowsBuild('build-win8');
slaves['crossplatform'] = createCrossplatfromBuild('build-os-x');
slaves['darwin'] = createDarwinBuild('build-os-x');
slaves['android'] = createAndroidBuild('build-os-x');
parallel slaves

stage 'Fingerprint'

node('master') {
    def branchSubPath =  env.BRANCH_NAME ? '/branches/' + env.BRANCH_NAME : ''
    def shortJobName = env.BRANCH_NAME ? env.JOB_NAME.replace('/' + env.BRANCH_NAME, '') : env.JOB_NAME
    def artifactsDir =
            env.JENKINS_HOME + '/jobs/' + shortJobName + branchSubPath + '/builds/' + env.BUILD_NUMBER + '/archive'
    dir(artifactsDir) {
        sh 'find . -type f -name "virgil-crypto-*" -exec sh -c "sha256sum {} | cut -d\' \' -f1-1 > {}.sha256" \\;'
    }
}

def createNativeUnixBuild(slave) {
    return {
        node(slave) {
            clearContentUnix()
            unstash 'src'
            // C++
            sh './utils/build.sh cpp'
            // Ruby
            withEnv(["PATH=${env.HOME}/.rbenv/bin:${env.PATH}"]){
                writeFile file: './utils/env.sh', text: ['eval "$(rbenv init -)"'].join("\n")
                writeFile file: '.ruby-version', text: ['2.0.0-p648'].join("\n")
                sh './utils/build.sh ruby-2.0'
                writeFile file: '.ruby-version', text: ['2.2.6'].join("\n")
                sh './utils/build.sh ruby-2.2'
                writeFile file: '.ruby-version', text: ['2.3.3'].join("\n")
                sh './utils/build.sh ruby-2.3'
                writeFile file: '.ruby-version', text: ['2.4.0'].join("\n")
                sh './utils/build.sh ruby-2.4'
            }
            organizeFilesUnix('install/ruby')
            // Python
            if (slave.contains('centos7')) {
                sh './utils/build.sh python-2.7'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/python33/enable', ''].join("\n")
                sh './utils/build.sh python-3.3'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-python34/enable', ''].join("\n")
                sh './utils/build.sh python-3.4'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-python35/enable', ''].join("\n")
                sh './utils/build.sh python-3.5'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-python36/enable', ''].join("\n")
                sh './utils/build.sh python-3.6'
                organizeFilesUnix('install/python')
            }
            if (slave.contains('build-os-x')) {
                sh './utils/build.sh python-2.7'
                sh './utils/build.sh python-3.4'
                sh './utils/build.sh python-3.5'
                sh './utils/build.sh python-3.6'
                organizeFilesUnix('install/python')
            }
            // Java
            sh './utils/build.sh java'
            // NodeJS
            sh './utils/build.sh nodejs-4.8.7'
            sh './utils/build.sh nodejs-6.13.0'
            sh './utils/build.sh nodejs-7.10.1'
            sh './utils/build.sh nodejs-8.9.4'
            sh './utils/build.sh nodejs-9.5.0'
            organizeFilesUnix('install/nodejs')
            // PHP
            if (slave.contains('os-x')) {
                def phpVersions = "php56 php70 php71"
                sh "brew unlink ${phpVersions} && brew link php56"
                sh "./utils/build.sh php-5.6"
                sh "brew unlink ${phpVersions} && brew link php70"
                sh "./utils/build.sh php-7.0"
                sh "brew unlink ${phpVersions} && brew link php71"
                sh "./utils/build.sh php-7.1"
                organizeFilesUnix('install/php')
            }
            if (slave.contains('centos7')) {
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                sh './utils/build.sh php-5.6'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php70/enable', ''].join("\n")
                sh './utils/build.sh php-7.0'
                writeFile file: './utils/env.sh', text: ['source /opt/remi/php71/enable', ''].join("\n")
                sh './utils/build.sh php-7.1'
                organizeFilesUnix('install/php')
            }
            //DotNET - Unix/Linux Mono
            if (! slave.contains('build-os-x')) {
                sh './utils/build.sh net'
            }

            archiveArtifacts('install/**')
        }
    }
}

def createNativeWindowsBuild(slave) {
    return {
        node(slave) {
            clearContentWindows()
            unstash 'src'
            withEnv(['MSVC_ROOT=C:\\Program Files (x86)\\Microsoft Visual Studio 14.0',
                     'JAVA_HOME=C:\\Program Files\\Java\\jdk1.8.0_65']) {
                bat 'utils\\build.bat cpp'
                bat 'utils\\build.bat net'
                bat 'utils\\build.bat java'
                bat 'utils\\build.bat nodejs-4.8.7'
                bat 'utils\\build.bat nodejs-6.13.0'
                bat 'utils\\build.bat nodejs-7.10.1'
                bat 'utils\\build.bat nodejs-8.9.4'
                bat 'utils\\build.bat nodejs-9.5.0'
                withEnv(["PATH=C:\\Python27_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-2.7-x86'
                }
                withEnv(["PATH=C:\\Python27_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-2.7-x64'
                }
                withEnv(["PATH=C:\\Python33_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.3-x86'
                }
                withEnv(["PATH=C:\\Python33_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.3-x64'
                }
                withEnv(["PATH=C:\\Python34_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.4-x86'
                }
                withEnv(["PATH=C:\\Python34_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.4-x64'
                }
                withEnv(["PATH=C:\\Python35_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.5-x86'
                }
                withEnv(["PATH=C:\\Python35_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.5-x64'
                }
                withEnv(["PATH=C:\\Python36_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.6-x86'
                }
                withEnv(["PATH=C:\\Python36_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.6-x64'
                }
            }
            organizeFilesWindows('install\\cpp')
            organizeFilesWindows('install\\net')
            organizeFilesWindows('install\\java')
            organizeFilesWindows('install\\nodejs')
            organizeFilesWindows('install\\python')
            archiveArtifacts('install/**')
        }
    }
}
def createCrossplatfromBuild(slave) {
    return {
        node(slave) {
            clearContentUnix()
            unstash 'src'
            withEnv(['EMSDK_HOME=/Users/virgil/Library/VirgilEnviroment/emsdk_portable']) {
                sh './utils/build.sh asmjs . build/asmjs install/asmjs'
                sh './utils/build.sh webasm . build/webasm install/webasm'
            }
            archiveArtifacts('install/**')
        }
    }
}

def createDarwinBuild(slave) {
    return {
        node(slave) {
            clearContentUnix()
            unstash 'src'
            sh 'rm -fr build install'
            sh './utils/build.sh macos . build/cpp/macos install/cpp/macos'
            sh './utils/build.sh ios . build/cpp/ios install/cpp/ios '
            sh './utils/build.sh watchos . build/cpp/watchos install/cpp/watchos'
            sh './utils/build.sh tvos . build/cpp/tvos install/cpp/tvos'
            sh './utils/build.sh net . build/net/macos install/net/macos'
            sh './utils/build.sh net_ios . build/net/ios install/net/ios'
            sh './utils/build.sh net_watchos . build/net/watchos install/net/watchos'
            sh './utils/build.sh net_tvos . build/net/tvos install/net/tvos'
            organizeFilesUnix('install/cpp')
            organizeFilesUnix('install/net')
            archiveArtifacts('install/**')
        }
    }
}

def createAndroidBuild(slave) {
    return {
        node(slave) {
            clearContentUnix()
            unstash 'src'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk']) {
                sh './utils/build.sh java_android . build/java/android install/java/android'
                sh './utils/build.sh net_android . build/net/android install/net/android'
            }
            organizeFilesUnix('install/java')
            organizeFilesUnix('install/net')
            archiveArtifacts('install/**')
        }
    }
}

def organizeFilesUnix(where) {
    sh "find ${where} -type f -mindepth 2 -name \"*.tgz\" -exec mv {} ${where} \\;"
    sh "find ${where} -type d -empty -delete"
}

def organizeFilesWindows(where) {
    bat "for /r \"${where}\" %%f in (*.zip) do move /y \"%%f\" \"${where}\""
    bat "(for /f \"delims=\" %%d in ('dir /s /b /a:d \"${where}\" ^^^| sort /r') do rmdir \"%%d\") || rem"
}

def clearContentWindows() {
    bat "(for /F \"delims=\" %%i in ('dir /b') do (rmdir \"%%i\" /s/q >nul 2>&1 || del \"%%i\" /s/q >nul 2>&1 )) || rem"
}

def clearContentUnix() {
    sh "rm -fr -- *"
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
