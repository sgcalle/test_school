# -*- coding: utf-8 -*-
# Part of Ktrine. See LICENSE file for full copyright and licensing details.

{
    'name': 'Blumon Pay Payment Acquirer',
    'category': 'Accounting/Payment Acquirers',
    'sequence': 365,
    'author': 'Ktrine Solutions S.A.',
    'summary': 'Payment Acquirer: Blumon Pay Implementation',
    'version': '1.0',
    'description': """Blumon Pay Payment Acquirer""",
    'depends': ['payment'],
    'contributors': [
        'Katerine Ricardo Aguilar: <katerineaguilar1216@gmail.com>',
        'Aime Álvarez Díaz',
        'Pedro Antonio Valdés Guibert <peterjunior0224@gmail.com>',
        'Pedro Perez Gonzälez',
        ],
    'data': [
        'views/payment_views.xml',
        'views/payment_blumonpay_templates.xml',
        'data/payment_acquirer_data.xml',
    ],
    'installable': True,
    'application': True,
    'post_init_hook': 'create_missing_journal_for_acquirers',
    'uninstall_hook': 'uninstall_hook',
}
