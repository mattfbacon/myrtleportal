declare type loggerOptions = {
  overwrite?: boolean,
  newline?: boolean
};
declare type outputOptions = {
  logOnly?: boolean,
  overwrite: boolean,
  color: string,
  newline: boolean
};

declare type userRow = {
  view: boolean,
  edit: boolean,
  download: boolean,
  username: string,
  id: number,
  password: string,
  email: string,
  admin: boolean
};
declare type basicEntryData = {
  name: string,
  descr: string,
  filename: string
};
declare type limitedEntryData = {
  path: string,
  name: string
};

declare type Links = {
  up?: string,
  first?: string,
  last?: string,
  previous?: string,
  next?: string
};

declare type RequestProps = {
  received: boolean;
  formData: { filename: string, defaultFilename?: string, includeMetadata?: string, metadataName?: string, metadataDescr?: string };
  invalid: boolean;
};
