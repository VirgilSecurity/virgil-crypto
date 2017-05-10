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
                organizeFilesUnix('install/python')
            }
            if (slave.contains('build-os-x')) {
                sh './utils/build.sh python-2.7'
                sh './utils/build.sh python-3.4'
                sh './utils/build.sh python-3.5'
                organizeFilesUnix('install/python')
            }
            // Java
            sh './utils/build.sh java'
            // NodeJS
            sh './utils/build.sh nodejs-4.1.0'
            sh './utils/build.sh nodejs-4.4.4'
            sh './utils/build.sh nodejs-5.9.1'
            sh './utils/build.sh nodejs-6.1.0'
            organizeFilesUnix('install/nodejs')
            // PHP
            sh './utils/build.sh php'
            if (slave.contains('centos7')) {
                writeFile file: './utils/env.sh', text: ['source /opt/rh/php55/enable', ''].join("\n")
                sh './utils/build.sh php-5.5'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                sh './utils/build.sh php-5.6'
                organizeFilesUnix('install/php')
            }
            //DotNET - Mono
            sh './utils/build.sh net'

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
                bat 'utils\\build.bat nodejs-4.1.0'
                bat 'utils\\build.bat nodejs-4.4.4'
                bat 'utils\\build.bat nodejs-5.9.1'
                bat 'utils\\build.bat nodejs-6.1.0'
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
                sh './utils/build.sh asmjs'
            }
            withEnv(['NACL_SDK_ROOT=/Users/virgil/Library/VirgilEnviroment/nacl_sdk/pepper_46']) {
                sh './utils/build.sh pnacl . build/cpp install/cpp'
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
            sh './utils/build.sh osx . build/cpp/osx install/cpp/osx'
            sh './utils/build.sh ios . build/cpp/ios install/cpp/ios '
            sh './utils/build.sh applewatchos . build/cpp/watchos install/cpp/watchos'
            sh './utils/build.sh appletvos . build/cpp/tvos install/cpp/tvos'
            sh './utils/build.sh net . build/net/osx install/net/osx'
            sh './utils/build.sh net_ios . build/net/ios install/net/ios'
            sh './utils/build.sh net_applewatchos . build/net/watchos install/net/watchos'
            sh './utils/build.sh net_appletvos . build/net/tvos install/net/tvos'
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
