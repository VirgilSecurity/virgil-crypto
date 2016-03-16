#!groovy
stage 'Grab SCM'

node('master') {
    sh 'rm -fr -- *'
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

def createNativeUnixBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            sh 'rm -fr build install'
            sh './utils/build.sh cpp'
            sh './utils/build.sh ruby'
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
            sh './utils/build.sh java'
            sh './utils/build.sh nodejs-0.12.7 . build/nodejs/0.12.7 install/nodejs/0.12.7'
            sh './utils/build.sh nodejs-4.1.0 . build/nodejs/4.1.0 install/nodejs/4.1.0'
            sh './utils/build.sh php'
            if (slave.contains('centos7')) {
                writeFile file: './utils/env.sh', text: ['source /opt/rh/php55/enable', ''].join("\n")
                sh './utils/build.sh php . build/php/php55 install/php/php55'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                sh './utils/build.sh php . build/php/php56 install/php/php56'
                organizeFilesUnix('install/php')
            }
            organizeFilesUnix('install/nodejs')
            archiveArtifacts('install/**')
        }
    }
}

def createNativeWindowsBuild(slave) {
    return {
        node(slave) {
            unstash 'src'
            bat 'if exist build rmdir /s/q build'
            bat 'if exist install rmdir /s/q install'
            withEnv(['MSVC_ROOT=C:\\Program Files (x86)\\Microsoft Visual Studio 14.0',
                     'JAVA_HOME=C:\\Program Files\\Java\\jdk1.8.0_65']) {
                bat 'utils\\build.bat cpp'
                bat 'utils\\build.bat net'
                bat 'utils\\build.bat java'
                bat 'utils\\build.bat nodejs-0.12.7 . build\\nodejs\\0.12.7 install\\nodejs\\0.12.7'
                bat 'utils\\build.bat nodejs-4.1.0 . build\\nodejs\\4.1.0 install\\nodejs\\4.1.0'
            }
            organizeFilesWindows('install\\cpp')
            organizeFilesWindows('install\\net')
            organizeFilesWindows('install\\java')
            organizeFilesWindows('install\\nodejs')
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
            organizeFilesUnix('install/cpp')
            organizeFilesUnix('install/net')
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
    bat "for /r \"${where}\" %%f in (*.zip) do move /y \"%%f\" \"${where}\" >nul"
    try {
        bat "for /f \"delims=\" %%d in ('dir /s /b /a:d \"${where}\" ^^^| sort /r 2^>nul') do rmdir \"%%d\""
    } catch(Exception exception) {
        // Ignore, because 'sort' can exit with error if no empty folders was found.
    }
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
