'use strict';

var builder = require('xmlbuilder');

exports.error = function (err, args) {
    console.error(err.message);
};

exports.success = function (result, args) {
    console.log(result);
};

exports.check = {};
exports.check.success = function (result, args) {

    var dependencies = [];
    var project = 'unknown';

    result.data.forEach(function (element) {
        project = element.path[0];

        var dependency = {
            dependency: {
                '@isVirtual': 'false',
                fileName: element.module + '@' + element.version,
                filePath: element.module + '@' + element.version,
                md5: '',
                sha1: '',
                description: element.title,
                identifiers: {
                    identifier: {
                        name: element.module,
                        '@type': 'nsp'
                    }
                },
                vulnerabilities: [{
                    vulnerability: {
                        '@source': 'NSP',
                        name: element.advisory,
                        cvssScore: element.cvss_score,
                        cvssAccessVector: element.cvss_vector,
                        cvssAccessComplexity: 'LOW',
                        cvssAuthenticationr: 'NONE',
                        cvssConfidentialImpact: 'NONE',
                        cvssIntegrityImpact: 'NONE',
                        cvssAvailabilityImpact: 'PARTIAL',
                        severity: 'Low',
                        description: element.overview + '||' + element.recommendation + ' vulnerable versions: ' + element.vulnerable_versions +
                        ' patched_versions: ' + element.patched_versions
                    }
                }]
            }
        };

        dependencies.push(dependency);
    });

    var result = {
        analysis: {
            '@xmlns': 'https://jeremylong.github.io/DependencyCheck/dependency-check.1.6.xsd',
            scanInfo: {
                engineVersion: '3.0.1'
            },
            projectInfo: {
                name: project,
                reportDate: new Date().toLocaleString(),
                credits: 'nsp'
            },
            dependencies: dependencies
        }
    };

    var xmlResult = builder.create(result, { encoding: 'utf-8', separateArrayItems: true });
    console.log(xmlResult.end({ pretty: true }));

};
