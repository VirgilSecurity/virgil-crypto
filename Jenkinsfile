#!groovy
stage 'Grab SCM'

node('master') {
    checkout scm
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

def createNativeUnixBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            sh 'rm -fr build install'
            sh './utils/build.sh cpp'
            sh './utils/build.sh ruby'
            sh './utils/build.sh python'
            sh './utils/build.sh java'
            sh './utils/build.sh nodejs-0.12.7 . build/nodejs/0.12.7 install/nodejs/0.12.7'
            sh './utils/build.sh nodejs-4.1.0 . build/nodejs/4.1.0 install/nodejs/4.1.0'
            sh './utils/build.sh php'
            if (slave.contains('centos7')) {
                cryptoEnvScript = '/tmp/virgil_crypto_env.sh'
                withEnv(["VIRGIL_CRYPTO_ENV_SCRIPT=\"${cryptoEnvScript}\""]) {
                    writeFile file: cryptoEnvScript, text: ['source /opt/rh/php55/enable', ''].join("\n")
                    sh './utils/build.sh php . build/php/php55 install/php/php55'
                    writeFile file: cryptoEnvScript, text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                    sh './utils/build.sh php . build/php/php56 install/php/php56'
                }
                sh "rm -f ${cryptoEnvScript}"
                organizeFilesUnix('*.tar.gz', 'install/php')
            }
            organizeFilesUnix('*.tar.gz', 'install/nodejs')
            archiveArtifacts('install/**')
        }
    }
}

def createNativeWindowsBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            withEnv(['MSVC_ROOT=C:\\Program Files (x86)\\Microsoft Visual Studio 14.0',
                     'JAVA_HOME=C:\\Program Files\\Java\\jdk1.8.0_65']) {
                bat 'utils\\build.bat cpp'
                bat 'utils\\build.bat net'
                bat 'utils\\build.bat java'
                bat 'utils\\build.bat nodejs-0.12.7 . build\\nodejs\\0.12.7 install\\nodejs\\0.12.7'
                bat 'utils\\build.bat nodejs-4.1.0 . build\\nodejs\\4.1.0 install\\nodejs\\4.1.0'
            }
            organizeFilesWindows('*.zip', 'install\\cpp')
            organizeFilesWindows('*.zip', 'install\\net')
            organizeFilesWindows('*.zip', 'install\\java')
            organizeFilesWindows('*.zip', 'install\\nodejs')
            archiveArtifacts('install/**')
        }
    }
}
def createCrossplatfromBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            sh 'rm -fr build install'
            withEnv(['EMSDK_HOME=/Users/virgil/Library/VirgilEnviroment/emsdk_portable']) {
                sh './utils/build.sh asmjs'
            }
            withEnv(['CROSSBRIDGE_HOME=/Users/virgil/Library/VirgilEnviroment/CrossBridge_15.0.0.3',
                     'FLEX_HOME=/Users/virgil/Library/VirgilEnviroment/flex_sdk_4.6']) {
                sh './utils/build.sh as3'
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
            unstash 'src'
            sh 'rm -fr build install'
            sh './utils/build.sh osx . build/cpp/osx install/cpp/osx'
            sh './utils/build.sh ios . build/cpp/ios install/cpp/ios '
            sh './utils/build.sh applewatchos . build/cpp/watchos install/cpp/watchos'
            sh './utils/build.sh appletvos . build/cpp/tvos install/cpp/tvos'
            sh './utils/build.sh net_ios . build/net/ios install/net/ios'
            sh './utils/build.sh net_applewatchos . build/net/watchos install/net/watchos'
            sh './utils/build.sh net_appletvos . build/net/tvos install/net/tvos'
            organizeFilesUnix('*.tar.gz', 'install/cpp')
            organizeFilesUnix('*.tar.gz', 'install/net')
            archiveArtifacts('install/**')
        }
    }
}

def createAndroidBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            sh 'rm -fr build install'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk']) {
                sh './utils/build.sh java_android . build/java/android install/java/android'
                sh './utils/build.sh net_android . build/net/android install/net/android'
            }
            organizeFilesUnix('*.tar.gz', 'install/java')
            organizeFilesUnix('*.tar.gz', 'install/net')
            archiveArtifacts('install/**')
        }
    }
}

def organizeFilesUnix(pattern, where) {
    sh "find ${where} -type f -mindepth 2 -name \"${pattern}\" -exec mv {} ${where} \\;"
    sh "find ${where} -type d -empty -delete"
}

def organizeFilesWindows(pattern, where) {
    bat "for /r \"${where}\" %%f in (${pattern}) do move /y \"%%f\" \"${where}\" >nul"
    bat "for /f \"delims=\" %%d in ('dir /s /b /ad \"${where}\" ^| sort /r') do rmdir \"%%d\""
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
