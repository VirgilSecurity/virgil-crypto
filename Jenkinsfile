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
                writeFile file: './utils/env.sh', text: ['source /opt/rh/php55/enable', ''].join("\n")
                sh './utils/build.sh php . build/php/php55 install/php/php55'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                sh './utils/build.sh php . build/php/php56 install/php/php56'
                organizeFiles('*.tar.gz', 'install/php')
            }
            organizeFiles('*.tar.gz', 'install/nodejs')
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
            organizeFiles('*.tar.gz', 'install/cpp')
            organizeFiles('*.tar.gz', 'install/net')
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
            organizeFiles('*.tar.gz', 'install/java')
            organizeFiles('*.tar.gz', 'install/net')
            archiveArtifacts('install/**')
        }
    }
}

def organizeFiles(pattern, where) {
    sh "find ${where} -type f -mindepth 2 -name \"${pattern}\" -exec mv {} ${where} \\;"
    sh "find ${where} -type d -empty -delete"
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
