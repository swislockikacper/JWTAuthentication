DROP TABLE IF EXISTS [dbo].[User]
GO

CREATE TABLE [dbo].[User]
(
    [Id] nvarchar(100) NOT NULL PRIMARY KEY,
    [EmailAddress] nvarchar(100) NOT NULL,
    [Password] varbinary(MAX) NOT NULL,
    [Salt] varbinary(MAX) NOT NULL,
    [FullName] nvarchar(200)
)
GO