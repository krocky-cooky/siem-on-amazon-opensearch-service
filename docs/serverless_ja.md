# OpenSearch Serverless へのデプロイ (Experimental)
<!-- markdownlint-disable-file MD033 -->

[In English](serverless.md) | [READMEに戻る](../README_ja.md)

Amazon OpenSearch Serverless ヘ SIEM on OpenSearch をデプロイする方法及び、注意事項を説明します

## はじめに

Amazon OpenSearch Serverless に SIEM on OpenSearch をデプロイすると、サービスの特徴や内部のバージョン等が違うことから、Managed Cluster とは以下の差があるのでご注意ください。

|違い|OpenSearch managed cluster|OpenSearch Serverless|
|----|--------------------------|---------------------|
|Index と Shard 管理|ユーザー自身で管理|サービス側で管理され、ユーザーによる管理は不要。自動スケール|
|Index と shard 数| 1 インスタンスで 1000 shard まで|[Time series コレクション]<br>120 indexまで<br>[Search コレクション]<br>20 indexまで<br>※ 下記のクォータを参照|
|[Security Analytics](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/security-analytics.html)|OpenSearch 2.5 以降で利用可能|未実装|
|Index 名と ローテーション|index 名に選択した年月日が付与され、自動でローテーションされる|index 名は固定で、連番を手動で付与 (例: log-aws-xxxx-001)|
|ログの重複排除|重複排除され、同じログはOpenSearch に Load されない|[Time series コレクション]<br>重複排除されない。同一の es-loader の Lambda インスタンスで処理された場合のみ重複排除される<br>[Search コレクション]<br>重複排除される|
|フィールドの ソートと集計|設定で変更可能。SIEM のデフォルト設定は 200 です|[doc_values](https://opensearch.org/docs/latest/field-types/supported-field-types/keyword/#parameters) は 100 フィールドまでです。フィールド数の多いログの取り込み時にはご注意ください|
|ログの削除| index単位の削除、<br>検索式(_delete_by_query)による削除 | index単位の削除 |
|OpenSearch API| [ほぼ全てのAPIをサポート](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/supported-operations.html)| [少なくとも reindex と snapshot は未サポート](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-genref.html) |

サービスとしての違いは公式ドキュメントをご参照ください

* [OpenSearch Service と OpenSearch Serverless を比較する](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-overview.html#serverless-comparison)
* [Amazon OpenSearch Service クォータ](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/limits.html)

## 事前準備

### VPC 内からのアクセス

VPC 内から OpenSearch Serverless にログを書き込む場合は、VPC に Amazon OpenSearch Serverless の VPC Endpoint を作成しておいてください。パブリックアクセスの場合は、この手順はスキップして下さい

1. VPC を作成
1. AOSS Endpoint を作成
1. tcp/443 のインバウンドを許可した Security Group を作成して、AOSS Endpoint に関連付け

### OpenSearch Serverless コレクション

AWS CDK または AWS CloudFormation テンプレートにて下記の OpenSearch Serverless のコレクションを新規作成します。この条件で問題ない場合は、この手順はスキップして下さい。

* コレクション名: パラメーターの DomainOrCollectionName で指定した名前
* コレクションタイプ: 時系列
* ネットワークアクセスタイプ: パブリック
* 暗号化: AWS 所有キー

違う条件のコレクションが必要な場合は、事前にご自身でコレクションを作成してください。

暗号化の鍵は [AWS 所有キー] のみ SIEM ソリューションでサポートしています

### NextGen コレクション

OpenSearch Serverless には Classic と NextGen の 2 つの世代があります。コンソールでコレクションを作ると、既定で NextGen になります。CDK / CloudFormation テンプレートが新規に作るコレクションは Classic です。

NextGen の時系列コレクションを使う場合は、事前にご自身でコレクショングループと時系列コレクションを作成し、`DomainOrCollectionName` にそのコレクション名を入力してください。

Classic との主な違い

|違い|Classic|NextGen|
|----|-------|-------|
|エンドポイント|`<id>.<region>.aoss.amazonaws.com`|`<id>.aoss.<region>.on.aws`|
|コレクショングループ|任意|必須|
|OpenSearch Dashboards|コレクションごとに提供|提供されない。[OpenSearch UI](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/application.html) を使う|
|ドキュメント ID の指定|時系列コレクションでは不可|時系列コレクションでは不可|
|タイムスタンプ|任意|`@timestamp` が無いドキュメントは拒否される|
|データの保持期間|データライフサイクルポリシー|index 設定の `index.data.retention`|

* SIEM は ID を付けずに書き込み、すべてのログに `@timestamp` を付けます
* NextGen ではダッシュボードは自動でインポートされません
* NextGen で VPC 内からアクセスするには標準の VPC エンドポイント (`com.amazonaws.<region>.aoss-data`) を使います。パラメーター `VpcEndpointId` はまだ対応していないため、パブリックのコレクションをご利用ください

詳細は [コレクションの作成](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-create.html) と [コレクションエンドポイント](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-collection-endpoints.html) をご参照ください

## SIEM のデプロイ

1. AWS CDK または CloudFormation テンプレートを実行する
1. パラメーター
    * `DeploymentTarget` に [opensearch_serverless] を選択
    * `DomainOrCollectionName` に [任意のコレクション名] を入力。既存のコレクションを使う場合は [既存のコレクション名] を入力
    * VPC 内からアクセスする場合は、`VpcEndpointId` に [AOSS Endpoint の ID] を入力
    * その他のパラメーターは、Managed Cluster でインストール場合と共通
1. OpenSearch Dashboards 用のデータアクセスポリシーの設定

## データアクセスポリシーの設定

CDK/CloudFormation ではデータアクセスポリシーは、ログの書き込みに必要なポリシーのみ設定されます。OpenSearch Dashboards を参照するために手動でポリシー設定をしてください。

設定例

1. 左のメニューから [データアクセスポリシー] を選択
1. [アクセスポリシーを作成] を選択
    1. アクセスポリシー名 に[任意のポリシー名]を入力。例: `dashboards-access`
    1. プリンシパルを選択 にアクセスを許可する IAM を入力
    1. リソースと許可を付与 の [付与] を選択
        1. エイリアスとテンプレートの許可 の [すべて選択] を選択
        1. コレクション名に CloudFormation で指定した [コレクション名] を入力
        1. インデックスの許可 の [すべて選択] を選択
        1. コレクション名に CloudFormation で指定した [コレクション名] を入力
        1. インデックス名は `*` を入力

## index のローテーション

デファオルトでは、インデックス名に001が付与されます。自動ローテーションはされません。例) `log-aws-cloudtrail-001`
ローテーションをする場合は、手動でsuffixを指定してください。

設定例

```ini
# user.ini
[cloudtrail]
index_suffix = 002
```

インデックス名: `log-aws-cloudtrail-002`

## シングルサインオンの実現

AWS IAM Identity Center によるシングルサインオンは [AWS Control Tower との統合 - SAML 認証](controltower_ja.md#saml-認証) をご参照ください

## Known Issue と制約

* ログの書込みに、「Internal error occurred while processing request」等の内部エラーが発生することがあります。自動でリトライ処理を行いますが、連続して失敗した場合は、ログは DLQ に移動します。SQS から再処理を実行して下さい
