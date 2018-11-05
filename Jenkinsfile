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
            sh './utils/build.sh --target=cpp'
            // Ruby
            withEnv(["PATH=${env.HOME}/.rbenv/bin:${env.PATH}"]){
                writeFile file: './utils/env.sh', text: ['eval "$(rbenv init -)"'].join("\n")
                writeFile file: '.ruby-version', text: ['2.0.0-p648'].join("\n")
                sh './utils/build.sh --target=ruby-2.0'
                writeFile file: '.ruby-version', text: ['2.2.6'].join("\n")
                sh './utils/build.sh --target=ruby-2.2'
                writeFile file: '.ruby-version', text: ['2.3.3'].join("\n")
                sh './utils/build.sh --target=ruby-2.3'
                writeFile file: '.ruby-version', text: ['2.4.0'].join("\n")
                sh './utils/build.sh --target=ruby-2.4'
            }
            organizeFilesUnix('install/ruby')
            // Python
            if (slave.contains('centos7')) {
                withEnv(["PATH=${env.HOME}/.pyenv/bin:${env.PATH}"]){
                    sh './utils/build.sh --target=python-2.7'
                    writeFile file: "./utils/python-env-vars.sh", text: [
                        'export PYTHON_INCLUDE_DIRS=\"$(python -c "from distutils.sysconfig import get_python_inc; print(get_python_inc())")\"',
                        'export PYTHON_LIBRARIES=\"$(python -c \'import distutils.sysconfig as sysconfig; print(sysconfig.get_config_var("LIBDIR"))\')\"',
                        'export PYTHON_INCLUDE_DIR="${PYTHON_INCLUDE_DIRS}"',
                        'export PYTHON_LIBRARY="${PYTHON_LIBRARIES}"'
                    ].join("\n")
                    writeFile file: './utils/env.sh', text: ['eval "$(pyenv init -)"', 'source python-env-vars.sh'].join("\n")
                    writeFile file: '.python-version', text: ['3.3.7'].join("\n")
                    sh './utils/build.sh --target=python-3.3; echo $PYTHON_INCLUDE_DIRS; echo $PYTHON_LIBRARIES'
                    writeFile file: '.python-version', text: ['3.4.9'].join("\n")
                    sh './utils/build.sh --target=python-3.4'
                    writeFile file: '.python-version', text: ['3.5.6'].join("\n")
                    sh './utils/build.sh --target=python-3.5'
                    writeFile file: '.python-version', text: ['3.6.7'].join("\n")
                    sh './utils/build.sh --target=python-3.6'
                    writeFile file: '.python-version', text: ['3.7.1'].join("\n")
                    sh './utils/build.sh --target=python-3.7'
                    organizeFilesUnix('install/python')
                }
            }
            if (slave.contains('build-os-x')) {
                sh './utils/build.sh --target=python-2.7'
                sh './utils/build.sh --target=python-3.4'
                sh './utils/build.sh --target=python-3.5'
                sh './utils/build.sh --target=python-3.6'
                sh './utils/build.sh --target=python-3.7'
                organizeFilesUnix('install/python')
            }
            // Java
            sh './utils/build.sh --target=java'
            // NodeJS
            sh './utils/build.sh --target=nodejs-4.9.1'
            sh './utils/build.sh --target=nodejs-6.14.2'
            sh './utils/build.sh --target=nodejs-7.10.1'
            sh './utils/build.sh --target=nodejs-8.11.2'
            sh './utils/build.sh --target=nodejs-9.11.1'
            sh './utils/build.sh --target=nodejs-10.1.0'
            organizeFilesUnix('install/nodejs')
            // PHP
            if (slave.contains('os-x')) {
                def phpVersions = "php56 php70 php71 php72"
                sh "brew unlink ${phpVersions} && brew link php56 --force"
                sh "./utils/build.sh --target=php-5.6"
                sh "brew unlink ${phpVersions} && brew link php70 --force"
                sh "./utils/build.sh --target=php-7.0"
                sh "brew unlink ${phpVersions} && brew link php71 --force"
                sh "./utils/build.sh --target=php-7.1"
                sh "brew unlink ${phpVersions} && brew link php72 --force"
                sh "./utils/build.sh --target=php-7.2"
                organizeFilesUnix('install/php')
            }
            if (slave.contains('centos7')) {
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php56/enable', ''].join("\n")
                sh './utils/build.sh --target=php-5.6'
                writeFile file: './utils/env.sh', text: ['source /opt/rh/rh-php70/enable', ''].join("\n")
                sh './utils/build.sh --target=php-7.0'
                writeFile file: './utils/env.sh', text: ['source /opt/remi/php71/enable', ''].join("\n")
                sh './utils/build.sh --target=php-7.1'
                writeFile file: './utils/env.sh', text: ['source /opt/remi/php72/enable', 'source /opt/rh/devtoolset-4/enable', ''].join("\n")
                sh './utils/build.sh --target=php-7.2'
                organizeFilesUnix('install/php')
            }
            // MONO NET
            sh './utils/build.sh --target=net'
            // Golang
            if (slave.contains('centos7') || slave.contains('os-x')) {
                sh './utils/build.sh --target=go'
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
                bat 'utils\\build.bat nodejs-4.9.1'
                bat 'utils\\build.bat nodejs-6.14.3'
                bat 'utils\\build.bat nodejs-7.10.1'
                bat 'utils\\build.bat nodejs-8.11.3'
                bat 'utils\\build.bat nodejs-9.11.2'
                bat 'utils\\build.bat nodejs-10.4.1'
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
                withEnv(["PATH=C:\\Python37_x86;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.7-x86'
                }
                withEnv(["PATH=C:\\Python37_x64;${env.PATH}"]) {
                    bat 'utils\\build.bat python-3.7-x64'
                }
            }
            withEnv(["MSVC_ROOT=C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community",
                     "PHP_HOME=C:\\php-7.2.6",
                     "PHP_DEVEL_HOME=C:\\php-7.2.6-devel",\
                     "PHPUNIT_HOME=C:\\phpunit-7.2.4"]) {

                bat 'utils\\build.bat php-7.2-x64'
            }
            organizeFilesWindows('install\\cpp')
            organizeFilesWindows('install\\net')
            organizeFilesWindows('install\\java')
            organizeFilesWindows('install\\nodejs')
            organizeFilesWindows('install\\python')
            organizeFilesWindows('install\\php')
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
                sh './utils/build.sh --target=asmjs --build=build/asmjs/basic --install=install/asmjs/basic'
                sh './utils/build.sh --target=asmjs --build=build/asmjs/pythia --install=install/asmjs/pythia --feature=pythia'
                sh './utils/build.sh --target=webasm --build=build/webasm/basic --install=install/webasm/basic'
                sh './utils/build.sh --target=webasm --build=build/webasm/pythia --install=install/webasm/pythia --feature=pythia'
            }
            organizeFilesUnix('install/asmjs')
            organizeFilesUnix('install/webasm')
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
            sh './utils/build.sh --target=macos --build=build/cpp/macos --install=install/cpp/macos'
            sh './utils/build.sh --target=ios --build=build/cpp/ios --install=install/cpp/ios '
            sh './utils/build.sh --target=watchos --build=build/cpp/watchos --install=install/cpp/watchos'
            sh './utils/build.sh --target=tvos --build=build/cpp/tvos --install=install/cpp/tvos'
            sh './utils/build.sh --target=net_ios --build=build/net/ios --install=install/net/ios'
            sh './utils/build.sh --target=net_watchos --build=build/net/watchos --install=install/net/watchos'
            sh './utils/build.sh --target=net_tvos --build=build/net/tvos --install=install/net/tvos'
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
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk-r16b']) {
                sh './utils/build.sh --target=java_android --build=build/java/android --install=install/java/android'
                sh './utils/build.sh --target=net_android --build=build/net/android --install=install/net/android'
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
